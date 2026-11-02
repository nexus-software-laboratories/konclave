/** Authenticated history metadata; a receipt never proves an ordinary text response. */
export type RequestDeliveryOutcome =
  'admitted' | 'expired_before_admission' | 'ended_without_response';

export function isRequestDeliveryOutcome(value: unknown): value is RequestDeliveryOutcome {
  return (
    value === 'admitted' ||
    value === 'expired_before_admission' ||
    value === 'ended_without_response'
  );
}
