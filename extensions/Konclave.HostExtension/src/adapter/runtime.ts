import type { AdapterChannel, AdapterListener, AdapterRendezvous } from './channel.js';
import { createDeliveryCoordinator, type DeliveryCoordinator } from './delivery.js';
import type { AdapterResponse, DeliveredEvent } from './session.js';

/**
 * How long one wait-and-claim blocks before the daemon answers empty.
 *
 * The daemon answers as soon as work exists, so this only bounds how long an idle
 * profile holds a request open.
 */
const claimWaitMilliseconds = 20_000;

/** Largest batch requested in one wait. */
const claimBatchSize = 20;

/** Default backoff after a rejected claim, so a broken channel cannot spin. */
export const defaultClaimRetryMilliseconds = 1_000;

export interface AdapterIntegration {
  createRendezvous(platform: NodeJS.Platform): Promise<AdapterRendezvous>;
  listen(rendezvous: AdapterRendezvous, platform: NodeJS.Platform): Promise<AdapterListener>;
}

export interface DeliveryRuntimeOptions {
  readonly channel: AdapterChannel;
  readonly coordinator: DeliveryCoordinator;
  readonly diagnostics: { error(message: string): void };
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly retryMilliseconds?: number;
}

export interface DeliveryRuntime {
  /** Resolves when the loop stops. */
  readonly completed: Promise<void>;
  /** Stops the loop after the outstanding wait returns. */
  stop(): void;
}

/**
 * Claims remote events and hands them to the delivery coordinator.
 *
 * The loop owns claiming only. Deciding when a claimed event may reach the session,
 * and whether it was accepted, belongs to the coordinator, so a change to wake policy
 * cannot accidentally alter claim or acknowledgment behaviour.
 */
export function startDeliveryRuntime(options: DeliveryRuntimeOptions): DeliveryRuntime {
  const sleep =
    options.sleep ??
    ((milliseconds: number) =>
      new Promise<void>((resolve) => {
        setTimeout(resolve, milliseconds).unref?.();
      }));
  const retryMilliseconds = options.retryMilliseconds ?? defaultClaimRetryMilliseconds;
  let running = true;

  const completed = (async () => {
    while (running) {
      let response: AdapterResponse;
      try {
        response = await options.channel.request({
          kind: 'wait-and-claim',
          maxEvents: claimBatchSize,
          waitMilliseconds: claimWaitMilliseconds,
        });
      } catch (error) {
        // A closed channel ends the loop; the extension reconnects by restarting.
        options.diagnostics.error(`Konclave claim failed: ${describeError(error)}`);
        return;
      }

      if (response.kind === 'failure') {
        options.diagnostics.error(`Konclave rejected a claim: ${response.code}`);
        await sleep(retryMilliseconds);
        continue;
      }

      if (response.kind !== 'batch') {
        options.diagnostics.error('Konclave answered a claim with an unexpected response.');
        await sleep(retryMilliseconds);
        continue;
      }

      if (response.events.length === 0) {
        // An expired wait is not an event, so the loop simply reissues.
        continue;
      }

      enqueue(options.coordinator, response.events, options.diagnostics);
      await options.coordinator.flush();
    }
  })();

  return {
    completed,
    stop() {
      running = false;
    },
  };
}

function enqueue(
  coordinator: DeliveryCoordinator,
  events: readonly DeliveredEvent[],
  diagnostics: { error(message: string): void },
): void {
  try {
    coordinator.enqueue(events);
  } catch (error) {
    diagnostics.error(`Konclave could not queue a delivery: ${describeError(error)}`);
  }
}

export { createDeliveryCoordinator };

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}
