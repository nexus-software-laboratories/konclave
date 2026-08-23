import { frameDelivery } from './framing.js';
import type { AdapterChannel } from './channel.js';
import { maxClaimBatch, type AdapterResponse, type DeliveredEvent } from './session.js';

/**
 * Coalescing and wake limits.
 *
 * A synthetic turn costs the user attention and model budget, so bursts become one
 * delivery and the number of wakes is capped independently overall and per
 * conversation. Reaching a budget delays delivery; it never acknowledges undelivered
 * work.
 */
export interface WakeBudget {
  /** Largest number of events folded into one synthetic turn. */
  readonly maxEventsPerTurn: number;
  /** Largest total peer text, in characters, folded into one turn. */
  readonly maxCharactersPerTurn: number;
  /** Largest number of synthetic turns within the window. */
  readonly maxTurnsPerWindow: number;
  /** Largest number of synthetic turns for one conversation within the window. */
  readonly maxTurnsPerConversationPerWindow: number;
  /** Budget window, in milliseconds. */
  readonly windowMs: number;
}

export const defaultWakeBudget: WakeBudget = {
  maxEventsPerTurn: 20,
  maxCharactersPerTurn: 8_000,
  maxTurnsPerWindow: 12,
  maxTurnsPerConversationPerWindow: 6,
  windowMs: 5 * 60_000,
};

export interface DeliverySession {
  send(message: string): Promise<string>;
}

export interface DeliveryDiagnostics {
  error(message: string): void;
}

export interface DeliveryClock {
  now(): number;
}

export interface DeliveryCoordinatorOptions {
  readonly channel: AdapterChannel;
  readonly session: DeliverySession;
  readonly diagnostics: DeliveryDiagnostics;
  readonly clock?: DeliveryClock;
  readonly budget?: WakeBudget;
}

export interface DeliveryCoordinator {
  /** Accepts a claimed batch for later delivery. */
  enqueue(events: readonly DeliveredEvent[]): void;
  /** Reports that the session became idle and may accept a synthetic turn. */
  markIdle(): Promise<void>;
  /** Reports that the session became active, so nothing may be injected. */
  markActive(): void;
  /** Number of claimed events waiting for an idle session. */
  readonly pending: number;
  /** Whether a synthetic turn is currently outstanding. */
  readonly outstanding: boolean;
}

interface TurnRecord {
  readonly at: number;
  readonly conversation: string;
}

/**
 * Queues claimed events and injects them only when the session is idle.
 *
 * Copilot's extension guidance warns against injecting into an active session, and a
 * second synthetic turn while one is outstanding would compound that, so at most one
 * turn is in flight at a time.
 *
 * An event is acknowledged only after the harness accepts the send. A failed send
 * releases the claim, so the event stays reclaimable rather than being lost. A crash
 * between acceptance and acknowledgment may redeliver the same stable notification
 * identifier, which the contract permits and the identifier makes recognizable.
 */
export function createDeliveryCoordinator(
  options: DeliveryCoordinatorOptions,
): DeliveryCoordinator {
  const budget = options.budget ?? defaultWakeBudget;
  const clock = options.clock ?? { now: () => Date.now() };
  const queue: DeliveredEvent[] = [];
  const turns: TurnRecord[] = [];
  let idle = false;
  let outstanding = false;

  const withinWindow = (now: number): TurnRecord[] => {
    while (turns.length > 0 && now - (turns[0]?.at ?? 0) >= budget.windowMs) {
      turns.shift();
    }
    return turns;
  };

  const budgetAllows = (now: number, conversation: string): boolean => {
    const recent = withinWindow(now);
    if (recent.length >= budget.maxTurnsPerWindow) {
      return false;
    }
    const forConversation = recent.filter((turn) => turn.conversation === conversation).length;
    return forConversation < budget.maxTurnsPerConversationPerWindow;
  };

  /**
   * Takes the events that fit in one turn for `conversation`.
   *
   * Only one conversation is taken, so a turn never mixes conversations and a
   * per-conversation budget stays meaningful.
   */
  const takeBatch = (conversation: string): DeliveredEvent[] => {
    const taken: DeliveredEvent[] = [];
    let characters = 0;

    for (let index = 0; index < queue.length;) {
      const event = queue[index];
      if (!event || event.conversation.toString('hex') !== conversation) {
        index += 1;
        continue;
      }

      const cost = event.payload.kind === 'application-text' ? event.payload.text.length : 0;
      if (taken.length > 0 && characters + cost > budget.maxCharactersPerTurn) {
        break;
      }

      taken.push(event);
      characters += cost;
      queue.splice(index, 1);

      if (taken.length >= budget.maxEventsPerTurn) {
        break;
      }
    }

    return taken;
  };

  /**
   * Returns the first queued conversation still within budget.
   *
   * Selecting only the head would let one busy conversation block every other
   * conversation behind it for the rest of the window, which is exactly the
   * starvation the per-conversation budget exists to prevent.
   */
  const selectConversation = (now: number): string | null => {
    const seen = new Set<string>();
    for (const event of queue) {
      const conversation = event.conversation.toString('hex');
      if (seen.has(conversation)) {
        continue;
      }
      seen.add(conversation);
      if (budgetAllows(now, conversation)) {
        return conversation;
      }
    }
    return null;
  };

  const settle = async (events: readonly DeliveredEvent[], accepted: boolean): Promise<void> => {
    for (const event of events) {
      try {
        const response = await options.channel.request({
          kind: accepted ? 'acknowledge' : 'release',
          notificationId: event.notificationId,
          leaseGeneration: event.leaseGeneration,
        });
        reportFailure(options.diagnostics, response);
      } catch (error) {
        options.diagnostics.error(`Konclave could not settle a delivery: ${describeError(error)}`);
      }
    }
  };

  const deliver = async (): Promise<void> => {
    if (outstanding || !idle || queue.length === 0) {
      return;
    }

    const now = clock.now();
    const conversation = selectConversation(now);
    if (conversation === null) {
      // Every queued conversation is at its budget. Work stays claimed; acknowledging
      // here would drop a message the session never saw.
      return;
    }

    const batch = takeBatch(conversation);
    if (batch.length === 0) {
      return;
    }

    outstanding = true;
    turns.push({ at: now, conversation });

    try {
      await options.session.send(frameDelivery(batch));
      await settle(batch, true);
    } catch (error) {
      options.diagnostics.error(`Konclave delivery was not accepted: ${describeError(error)}`);
      await settle(batch, false);
    } finally {
      outstanding = false;
    }
  };

  return {
    enqueue(events) {
      if (events.length > maxClaimBatch) {
        throw new Error('adapter request is outside its bound');
      }
      queue.push(...events);
    },
    async markIdle() {
      idle = true;
      await deliver();
    },
    markActive() {
      idle = false;
    },
    get pending() {
      return queue.length;
    },
    get outstanding() {
      return outstanding;
    },
  };
}

function reportFailure(diagnostics: DeliveryDiagnostics, response: AdapterResponse): void {
  if (response.kind === 'failure') {
    diagnostics.error(`Konclave rejected a delivery transition: ${response.code}`);
  }
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}
