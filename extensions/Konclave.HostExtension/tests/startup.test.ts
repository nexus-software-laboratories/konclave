import { describe, expect, it } from 'vitest';

import { resolveExtensionStartupFailure, type ExtensionStartupStage } from '../src/startup.js';

describe('extension startup failure policy', () => {
  const cases: ReadonlyArray<{
    readonly stage: ExtensionStartupStage;
    readonly kind: 'degraded' | 'fatal';
    readonly joinSession: boolean;
    readonly registerCommand: boolean;
  }> = [
    {
      stage: 'profile',
      kind: 'fatal',
      joinSession: false,
      registerCommand: false,
    },
    {
      stage: 'service',
      kind: 'degraded',
      joinSession: true,
      registerCommand: true,
    },
    {
      stage: 'session',
      kind: 'fatal',
      joinSession: false,
      registerCommand: false,
    },
  ];

  for (const testCase of cases) {
    it(`classifies ${testCase.stage} failure`, () => {
      expect(resolveExtensionStartupFailure(testCase.stage)).toEqual({
        kind: testCase.kind,
        joinSession: testCase.joinSession,
        registerCommand: testCase.registerCommand,
        registerTools: false,
        startDelivery: false,
      });
    });
  }
});
