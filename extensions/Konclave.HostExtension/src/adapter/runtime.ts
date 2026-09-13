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
export const maximumHeartbeatRetryMilliseconds = 5_000;

/** Largest batch requested in one wait. */
/** Default backoff after a rejected claim, so a broken channel cannot spin. */
export const defaultClaimRetryMilliseconds = 1_000;
export const maximumClaimRetryMilliseconds = 30_000;

type DeliveryFailureClass =
  | 'heartbeat-rejected'
  | 'heartbeat-protocol'
  | 'heartbeat-transport'
  | 'claim-rejected'
  | 'claim-protocol'
  | 'claim-transport';

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
  let outageFailures = 0;
  const reportedFailureClasses = new Set<DeliveryFailureClass>();
  let lastHeartbeatAt = clock.now() - heartbeatMilliseconds;

  const reportFailure = (failureClass: DeliveryFailureClass, message: string): void => {
    consecutiveFailures = Math.min(Number.MAX_SAFE_INTEGER, consecutiveFailures + 1);
    outageFailures = Math.min(Number.MAX_SAFE_INTEGER, outageFailures + 1);
    const firstOfClass = !reportedFailureClasses.has(failureClass);
    reportedFailureClasses.add(failureClass);
    if (firstOfClass || Number.isInteger(Math.log2(outageFailures))) {
      options.diagnostics.error(
        outageFailures === 1 ? message : `${message} (outage failure ${outageFailures})`,
      );
    }
  };

  const resetFailures = (): void => {
    consecutiveFailures = 0;
    outageFailures = 0;
    reportedFailureClasses.clear();
  };

  const retryDelay = (maximum = maximumClaimRetryMilliseconds): number => {
    const exponent = Math.min(Math.max(0, consecutiveFailures - 1), 10);
    const raw = Math.min(maximum, retryMilliseconds * 2 ** exponent);
    const profileSpread =
      [...options.channel.profile].reduce((sum, value) => sum + value.charCodeAt(0), 0) % 401;
    return Math.min(maximum, Math.round(raw * (0.8 + profileSpread / 1_000)));
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
              reportFailure(
                'heartbeat-rejected',
                `Konclave rejected a heartbeat: ${heartbeat.code}`,
              );
              await sleep(retryDelay(maximumHeartbeatRetryMilliseconds));
              continue;
            }
            if (heartbeat.kind !== 'accepted') {
              reportFailure(
                'heartbeat-protocol',
                'Konclave answered a delivery heartbeat with an unexpected response.',
              );
              await sleep(retryDelay(maximumHeartbeatRetryMilliseconds));
              continue;
            }
            lastHeartbeatAt = now;
            resetFailures();
          } catch {
            if (!running) {
              return;
            }
            reportFailure('heartbeat-transport', 'Konclave heartbeat transport failed.');
            await sleep(retryDelay(maximumHeartbeatRetryMilliseconds));
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
      } catch {
        if (!running) {
          return;
        }
        reportFailure('claim-transport', 'Konclave claim transport failed.');
        await sleep(retryDelay());
        continue;
      }

      if (response.kind === 'failure') {
        reportFailure('claim-rejected', `Konclave rejected a claim: ${response.code}`);
        await sleep(retryDelay());
        continue;
      }

      if (response.kind !== 'batch') {
        reportFailure('claim-protocol', 'Konclave answered a claim with an unexpected response.');
        await sleep(retryDelay());
        continue;
      }

      if (response.events.length === 0) {
        resetFailures();
        // An expired wait is not an event, so the loop simply reissues.
        continue;
      }

      resetFailures();
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
  } catch {
    diagnostics.error('Konclave could not queue a delivery.');
  }
}

export { createDeliveryCoordinator };
