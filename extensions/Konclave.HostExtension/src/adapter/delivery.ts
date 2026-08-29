import { frameDelivery } from './framing.js';
import {
  type CollaborationTurnAuthorization,
  type CollaborationTurnDecision,
  maxClaimBatch,
  type AdapterChannel,
  type AdapterResponse,
  type DeliveredEvent,
} from './session.js';

/**
 * Coalescing and wake limits.
 *
 * A directed request costs user attention and model budget, so request bodies and
 * wakes are bounded independently overall and per conversation. Terminal updates do
 * not consume this budget.
 */
export interface WakeBudget {
  /** Must remain one for the exact-request turn contract. */
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
  maxEventsPerTurn: 1,
  maxCharactersPerTurn: 8_000,
  maxTurnsPerWindow: 12,
  maxTurnsPerConversationPerWindow: 6,
  windowMs: 5 * 60_000,
};
const deferredRetryMilliseconds = 20_000;

export interface DeliverySession {
  send(message: { readonly prompt: string; readonly mode: 'enqueue' }): Promise<string>;
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
  readonly authorizeTurn?: (
    events: readonly DeliveredEvent[],
  ) => Promise<CollaborationTurnDecision | null>;
  readonly completeAuthorizedTurn?: (
    authorization: CollaborationTurnAuthorization,
  ) => Promise<'completed-response' | 'completed-no-response'>;
  readonly canCompleteAuthorizedTurn?: (authorization: CollaborationTurnAuthorization) => boolean;
  readonly activateAuthorizedTurn?: (authorization: CollaborationTurnAuthorization) => void;
  readonly clearAuthorizedTurn?: () => void;
}

export interface DeliveryCoordinator {
  /** Accepts a claimed batch for later delivery. */
  enqueue(events: readonly DeliveredEvent[]): void;
  /** Reports that the session became idle and may accept a synthetic turn. */
  markIdle(): Promise<void>;
  /** Reports that the session became active, so nothing may be injected. */
  markActive(): void;
  /**
   * Attempts a delivery without changing the idle state.
   *
   * Newly claimed work must not itself make a busy session look idle, so claiming and
   * idle observation stay separate inputs.
   */
  flush(): Promise<void>;
  /** Number of claimed events waiting for an idle session. */
  readonly pending: number;
  /** Whether a synthetic turn is currently outstanding. */
  readonly outstanding: boolean;
  /** Exact handling claim that may be renewed while its turn is outstanding. */
  readonly activeTurn: CollaborationTurnAuthorization | null;
}

interface TurnRecord {
  readonly at: number;
  readonly conversation: string;
}

interface InFlightTurn {
  readonly event: DeliveredEvent;
  readonly authorization: CollaborationTurnAuthorization;
}

function isDeferredDecision(
  decision: CollaborationTurnDecision | null,
): decision is { readonly kind: 'deferred' } {
  return decision !== null && 'kind' in decision && decision.kind === 'deferred';
}

/**
 * Queues claimed events and injects them only when the session is idle.
 *
 * Copilot's extension guidance warns against injecting into an active session, and a
 * second synthetic turn while one is outstanding would compound that, so at most one
 * turn is in flight at a time.
 *
 * A directed request is acknowledged only after its durable handling outcome.
 * Terminal updates are acknowledged after a body-free local diagnostic. A crash
 * before acknowledgment may redeliver the same stable notification identifier.
 */
export function createDeliveryCoordinator(
  options: DeliveryCoordinatorOptions,
): DeliveryCoordinator {
  const budget = options.budget ?? defaultWakeBudget;
  if (
    budget.maxEventsPerTurn !== 1 ||
    !Number.isSafeInteger(budget.maxCharactersPerTurn) ||
    budget.maxCharactersPerTurn < 1 ||
    !Number.isSafeInteger(budget.maxTurnsPerWindow) ||
    budget.maxTurnsPerWindow < 1 ||
    !Number.isSafeInteger(budget.maxTurnsPerConversationPerWindow) ||
    budget.maxTurnsPerConversationPerWindow < 1 ||
    budget.maxTurnsPerConversationPerWindow > budget.maxTurnsPerWindow ||
    !Number.isSafeInteger(budget.windowMs) ||
    budget.windowMs < 1
  ) {
    throw new Error('the directed-request wake budget is invalid');
  }
  const clock = options.clock ?? { now: () => Date.now() };
  const queue: DeliveredEvent[] = [];
  const turns: TurnRecord[] = [];
  const deferredUntil = new Map<string, number>();
  let idle = false;
  let outstanding = false;
  let inFlight: InFlightTurn | null = null;

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

  /** Removes one bounded batch of terminal updates that never enter a model turn. */
  const takeTerminalBatch = (): DeliveredEvent[] => {
    const taken: DeliveredEvent[] = [];
    for (let index = 0; index < queue.length;) {
      const event = queue[index];
      if (!event || event.payload.kind === 'directed-request') {
        index += 1;
        continue;
      }
      taken.push(event);
      queue.splice(index, 1);
      if (taken.length >= maxClaimBatch) {
        break;
      }
    }
    return taken;
  };

  const takeDirectedRequest = (conversation: string): DeliveredEvent | null => {
    const index = queue.findIndex(
      (event) =>
        event.payload.kind === 'directed-request' &&
        event.conversation.toString('hex') === conversation,
    );
    if (index < 0) {
      return null;
    }
    return queue.splice(index, 1)[0] ?? null;
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
      if (
        event.payload.kind === 'directed-request' &&
        (deferredUntil.get(event.notificationId.toString('hex')) ?? 0) > now
      ) {
        continue;
      }
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

  const completeTurn = async (turn: InFlightTurn): Promise<boolean> => {
    try {
      if (!options.completeAuthorizedTurn) {
        throw new Error('the authorized delivery completion boundary is unavailable');
      }
      await options.completeAuthorizedTurn(turn.authorization);
      return true;
    } catch (error) {
      options.diagnostics.error(
        `Konclave could not complete an authorized turn: ${describeError(error)}`,
      );
      return false;
    } finally {
      options.clearAuthorizedTurn?.();
    }
  };

  const deliver = async (): Promise<void> => {
    if (outstanding || !idle || queue.length === 0) {
      return;
    }

    const terminal = takeTerminalBatch();
    if (terminal.length > 0) {
      outstanding = true;
      options.diagnostics.error(
        'Konclave retained a terminal update in message history; no automatic turn was started.',
      );
      await settle(terminal, true);
      outstanding = false;
      return deliver();
    }

    const now = clock.now();
    const conversation = selectConversation(now);
    if (conversation === null) {
      // Every queued conversation is at its budget. Work stays claimed; acknowledging
      // here would drop a message the session never saw.
      return;
    }

    const request = takeDirectedRequest(conversation);
    if (!request) {
      return;
    }

    outstanding = true;
    if (
      request.payload.kind !== 'directed-request' ||
      request.payload.text.length > budget.maxCharactersPerTurn
    ) {
      options.diagnostics.error(
        'Konclave retained a directed request outside the automatic turn budget.',
      );
      await settle([request], true);
      outstanding = false;
      return deliver();
    }
    let authorization: CollaborationTurnAuthorization | null = null;

    try {
      if (!options.authorizeTurn || !options.completeAuthorizedTurn) {
        throw new Error('the directed-request handling boundary is unavailable');
      }
      const decision = await options.authorizeTurn([request]);
      if (isDeferredDecision(decision)) {
        deferredUntil.set(request.notificationId.toString('hex'), now + deferredRetryMilliseconds);
        queue.push(request);
        outstanding = false;
        return;
      }
      deferredUntil.delete(request.notificationId.toString('hex'));
      authorization = decision;
      if (!authorization) {
        options.diagnostics.error(
          'Konclave retained a directed request in message history; no automatic turn was authorized.',
        );
        await settle([request], true);
        outstanding = false;
        return deliver();
      }
      options.activateAuthorizedTurn?.(authorization);
      inFlight = { event: request, authorization };
      turns.push({ at: now, conversation });
      await options.session.send({
        prompt: frameDelivery([request], authorization),
        mode: 'enqueue',
      });
    } catch (error) {
      let accepted = false;
      if (authorization && inFlight) {
        accepted = await completeTurn(inFlight);
        inFlight = null;
      } else if (authorization) {
        options.clearAuthorizedTurn?.();
      }
      options.diagnostics.error(`Konclave delivery was not accepted: ${describeError(error)}`);
      await settle([request], accepted);
      outstanding = false;
      return deliver();
    }
  };

  const finishInFlight = async (): Promise<void> => {
    const turn = inFlight;
    if (!turn) {
      options.clearAuthorizedTurn?.();
      return;
    }
    if (!options.canCompleteAuthorizedTurn?.(turn.authorization)) {
      return;
    }
    const accepted = await completeTurn(turn);
    inFlight = null;
    await settle([turn.event], accepted);
    outstanding = false;
  };

  return {
    enqueue(events) {
      if (events.length > maxClaimBatch) {
        throw new Error('adapter request is outside its bound');
      }
      const retained = new Set(queue.map((event) => event.notificationId.toString('hex')));
      for (const event of events) {
        retained.add(event.notificationId.toString('hex'));
      }
      if (retained.size > maxClaimBatch) {
        throw new Error('adapter queue is outside its bound');
      }
      for (const event of events) {
        const queued = queue.findIndex((candidate) =>
          candidate.notificationId.equals(event.notificationId),
        );
        if (queued >= 0) {
          const existing = queue[queued];
          if (existing && event.leaseGeneration > existing.leaseGeneration) {
            queue[queued] = event;
            deferredUntil.delete(event.notificationId.toString('hex'));
          }
          continue;
        }
        if (
          inFlight?.event.notificationId.equals(event.notificationId) &&
          event.leaseGeneration <= inFlight.event.leaseGeneration
        ) {
          continue;
        }
        queue.push(event);
      }
    },
    async markIdle() {
      idle = true;
      await finishInFlight();
      await deliver();
    },
    markActive() {
      idle = false;
    },
    async flush() {
      await deliver();
    },
    get pending() {
      return queue.length;
    },
    get outstanding() {
      return outstanding;
    },
    get activeTurn() {
      return inFlight?.authorization ?? null;
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
