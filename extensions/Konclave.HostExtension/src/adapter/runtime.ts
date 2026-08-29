import { performance } from 'node:perf_hooks';

import {
  createDeliveryCoordinator,
  type DeliveryClock,
  type DeliveryCoordinator,
} from './delivery.js';
import {
  maxClaimBatch,
  type AdapterChannel,
  type AdapterResponse,
  type DeliveredEvent,
} from './session.js';

/**
 * How long one wait-and-claim blocks before the daemon answers empty.
 *
 * The daemon answers as soon as work exists, so this only bounds how long an idle
 * profile holds a request open.
 */
const claimWaitMilliseconds = 20_000;
const backpressurePollMilliseconds = 250;
const heartbeatMilliseconds = 20_000;

/** Largest batch requested in one wait. */
/** Default backoff after a rejected claim, so a broken channel cannot spin. */
export const defaultClaimRetryMilliseconds = 1_000;
export const maximumClaimRetryMilliseconds = 30_000;

export interface DeliveryRuntimeOptions {
  readonly channel: AdapterChannel;
  readonly coordinator: DeliveryCoordinator;
  readonly diagnostics: { error(message: string): void };
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly clock?: DeliveryClock;
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
 * The loop owns claiming and claim heartbeats. While the coordinator retains work,
 * it renews existing leases instead of claiming an unbounded queue. Deciding when a
 * claimed event may reach the session, and whether it was accepted, belongs to the
 * coordinator.
 */
export function startDeliveryRuntime(options: DeliveryRuntimeOptions): DeliveryRuntime {
  const sleep =
    options.sleep ??
    ((milliseconds: number) =>
      new Promise<void>((resolve) => {
        setTimeout(resolve, milliseconds).unref?.();
      }));
  const retryMilliseconds = options.retryMilliseconds ?? defaultClaimRetryMilliseconds;
  const clock = options.clock ?? { now: () => performance.now() };
  let running = true;
  let consecutiveFailures = 0;
  let lastHeartbeatAt = clock.now() - heartbeatMilliseconds;

  const retryDelay = (): number => {
    const exponent = Math.min(Math.max(0, consecutiveFailures - 1), 10);
    const raw = Math.min(maximumClaimRetryMilliseconds, retryMilliseconds * 2 ** exponent);
    const profileSpread =
      [...options.channel.profile].reduce((sum, value) => sum + value.charCodeAt(0), 0) % 401;
    return Math.min(maximumClaimRetryMilliseconds, Math.round(raw * (0.8 + profileSpread / 1_000)));
  };

  const completed = (async () => {
    while (running) {
      if (options.coordinator.outstanding || options.coordinator.pending > 0) {
        await options.coordinator.flush();
        if (!options.coordinator.outstanding && options.coordinator.pending === 0) {
          continue;
        }
        const now = clock.now();
        if (now - lastHeartbeatAt >= heartbeatMilliseconds) {
          try {
            const heartbeat = await options.channel.request({
              kind: 'heartbeat',
              turn: options.coordinator.activeTurn ?? undefined,
            });
            if (heartbeat.kind === 'failure') {
              options.diagnostics.error(`Konclave rejected a heartbeat: ${heartbeat.code}`);
              consecutiveFailures += 1;
              await sleep(retryDelay());
              continue;
            }
            if (heartbeat.kind !== 'accepted') {
              options.diagnostics.error(
                'Konclave answered a delivery heartbeat with an unexpected response.',
              );
              consecutiveFailures += 1;
              await sleep(retryDelay());
              continue;
            }
            lastHeartbeatAt = now;
            consecutiveFailures = 0;
          } catch (error) {
            if (!running) {
              return;
            }
            options.diagnostics.error(`Konclave heartbeat failed: ${describeError(error)}`);
            consecutiveFailures += 1;
            await sleep(retryDelay());
            continue;
          }
        }
        await sleep(backpressurePollMilliseconds);
        continue;
      }
      let response: AdapterResponse;
      try {
        response = await options.channel.request({
          kind: 'wait-and-claim',
          maxEvents: maxClaimBatch,
          waitMilliseconds: claimWaitMilliseconds,
        });
      } catch (error) {
        if (!running) {
          return;
        }
        options.diagnostics.error(`Konclave claim failed: ${describeError(error)}`);
        consecutiveFailures += 1;
        await sleep(retryDelay());
        continue;
      }

      if (response.kind === 'failure') {
        options.diagnostics.error(`Konclave rejected a claim: ${response.code}`);
        consecutiveFailures += 1;
        await sleep(retryDelay());
        continue;
      }

      if (response.kind !== 'batch') {
        options.diagnostics.error('Konclave answered a claim with an unexpected response.');
        consecutiveFailures += 1;
        await sleep(retryDelay());
        continue;
      }

      if (response.events.length === 0) {
        consecutiveFailures = 0;
        // An expired wait is not an event, so the loop simply reissues.
        continue;
      }

      consecutiveFailures = 0;
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
