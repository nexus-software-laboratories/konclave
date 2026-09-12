import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { maxClaimBatch, maxEventTextBytes, maxWaitMilliseconds } from '../src/adapter/session.js';
import { deliveryOperations, serviceOperations } from '../src/service/operations.js';

interface AdapterFixture {
  readonly adapterApiVersion: number;
  readonly operations: {
    readonly claim: string;
    readonly acknowledge: string;
    readonly release: string;
    readonly heartbeat: string;
    readonly status: string;
  };
  readonly limits: {
    readonly maxClaimBatch: number;
    readonly maxWaitMilliseconds: number;
    readonly maxEventTextBytes: number;
    readonly recommendedHeartbeatMilliseconds: number;
  };
  readonly lifecycle: {
    readonly ambiguousClaimRecovery: string;
    readonly pollingFallback: string;
  };
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function record(value: unknown, field: string): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) {
    throw new Error(`adapter fixture ${field} must be an object`);
  }
  return value;
}

function string(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new Error(`adapter fixture ${field} must be a string`);
  }
  return value;
}

function integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`adapter fixture ${field} must be a nonnegative integer`);
  }
  return value;
}

function parseFixture(value: unknown): AdapterFixture {
  const fixture = record(value, 'root');
  const operations = record(fixture.operations, 'operations');
  const limits = record(fixture.limits, 'limits');
  const lifecycle = record(fixture.lifecycle, 'lifecycle');
  return {
    adapterApiVersion: integer(fixture.adapterApiVersion, 'adapterApiVersion'),
    operations: {
      claim: string(operations.claim, 'operations.claim'),
      acknowledge: string(operations.acknowledge, 'operations.acknowledge'),
      release: string(operations.release, 'operations.release'),
      heartbeat: string(operations.heartbeat, 'operations.heartbeat'),
      status: string(operations.status, 'operations.status'),
    },
    limits: {
      maxClaimBatch: integer(limits.maxClaimBatch, 'limits.maxClaimBatch'),
      maxWaitMilliseconds: integer(limits.maxWaitMilliseconds, 'limits.maxWaitMilliseconds'),
      maxEventTextBytes: integer(limits.maxEventTextBytes, 'limits.maxEventTextBytes'),
      recommendedHeartbeatMilliseconds: integer(
        limits.recommendedHeartbeatMilliseconds,
        'limits.recommendedHeartbeatMilliseconds',
      ),
    },
    lifecycle: {
      ambiguousClaimRecovery: string(
        lifecycle.ambiguousClaimRecovery,
        'lifecycle.ambiguousClaimRecovery',
      ),
      pollingFallback: string(lifecycle.pollingFallback, 'lifecycle.pollingFallback'),
    },
  };
}

const rawFixture: unknown = JSON.parse(
  readFileSync(
    new URL('../../../fixtures/local-service/v1/adapter-delivery.json', import.meta.url),
    'utf8',
  ),
);
const fixture = parseFixture(rawFixture);

describe('harness-neutral adapter contract', () => {
  it('matches the shared local-service operations and bounds', () => {
    expect(fixture.adapterApiVersion).toBe(1);
    expect(fixture.operations).toEqual({
      claim: deliveryOperations.claim,
      acknowledge: deliveryOperations.acknowledge,
      release: deliveryOperations.release,
      heartbeat: deliveryOperations.heartbeat,
      status: serviceOperations.status,
    });
    expect(fixture.limits).toEqual({
      maxClaimBatch,
      maxWaitMilliseconds,
      maxEventTextBytes,
      recommendedHeartbeatMilliseconds: 30_000,
    });
  });

  it('keeps polling integrations explicitly best effort', () => {
    expect(fixture.lifecycle.pollingFallback).toContain('best effort');
    expect(fixture.lifecycle.ambiguousClaimRecovery).toContain('fresh request identifier');
    expect(JSON.stringify(fixture.operations)).not.toMatch(/copilot|claude|codex|prompt|model/u);
  });
});
