export type ExtensionStartupStage = 'profile' | 'service' | 'session';

export type ExtensionStartupFailure =
  | {
      readonly kind: 'degraded';
      readonly joinSession: true;
      readonly registerCommand: true;
      readonly registerTools: false;
      readonly startDelivery: false;
    }
  | {
      readonly kind: 'fatal';
      readonly joinSession: false;
      readonly registerCommand: false;
      readonly registerTools: false;
      readonly startDelivery: false;
    };

export function resolveExtensionStartupFailure(
  stage: ExtensionStartupStage,
): ExtensionStartupFailure {
  if (stage === 'service') {
    return {
      kind: 'degraded',
      joinSession: true,
      registerCommand: true,
      registerTools: false,
      startDelivery: false,
    };
  }

  return {
    kind: 'fatal',
    joinSession: false,
    registerCommand: false,
    registerTools: false,
    startDelivery: false,
  };
}
