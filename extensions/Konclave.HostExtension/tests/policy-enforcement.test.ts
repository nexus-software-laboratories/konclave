import { describe, expect, it, vi } from 'vitest';

import { createDeliveryCoordinator } from '../src/adapter/delivery.js';
import type { DeliveredEvent } from '../src/adapter/session.js';
import type { LocalServiceClient } from '../src/service/client.js';
import { attachLocalFailure } from '../src/service/failure-diagnostics.js';
import {
  createCopilotPolicyGate,
  type CopilotPolicyGate,
} from '../src/service/policy-enforcement.js';
import {
  collaborationAuthorizationArgument,
  collaborationTurnTokenLabel,
} from '../src/collaboration-contract.js';

const conversation = '11'.repeat(32);
const policyDigest = '22'.repeat(32);

function client(request: LocalServiceClient['request']): LocalServiceClient {
  return {
    profile: 'session-policy-gate',
    request,
    retire: vi.fn().mockResolvedValue(undefined),
    close: vi.fn(),
    connected: true,
  };
}

function event(value = 0x11): DeliveredEvent {
  return {
    notificationId: Buffer.alloc(16, 1),
    leaseGeneration: 1,
    sequence: 1,
    conversation: Buffer.alloc(32, value),
    sender: Buffer.alloc(32, 3),
    relayCursor: 1,
    payload: { kind: 'application-text', text: 'review the contract' },
  };
}

function requestEvent(): DeliveredEvent {
  return {
    ...event(),
    payload: {
      kind: 'directed-request',
      messageId: Buffer.alloc(16, 0x66),
      target: Buffer.alloc(32, 0x11),
      text: 'review the contract',
    },
  };
}

function hookInput(toolName: string, toolArgs: unknown) {
  return {
    sessionId: 'session',
    timestamp: new Date(0),
    workingDirectory: 'workspace',
    toolName,
    toolArgs,
  };
}

function activateGate(gate: CopilotPolicyGate, workAllowed = false): void {
  const turnToken = '33'.repeat(16);
  gate.activate({
    conversation,
    policyDigest,
    policyName: 'contract-alignment',
    requestMessageId: '66'.repeat(16),
    attempt: 1,
    turnToken,
    workAllowed,
  });
  gate.observePrompt(`Konclave delivered 1 update\n${collaborationTurnTokenLabel}: ${turnToken}`);
}

describe('Copilot collaboration policy gate', () => {
  it('requires exact native answer evidence and current work authority', async () => {
    const answer: DeliveredEvent = {
      ...event(),
      payload: {
        kind: 'application-text',
        messageId: Buffer.alloc(16, 0x77),
        replyToMessageId: Buffer.alloc(16, 0x66),
        text: 'review feedback',
      },
    };
    for (const evidence of [
      { continuationMessageId: '77'.repeat(16), workAllowed: true },
      { continuationMessageId: '78'.repeat(16), workAllowed: true },
      { continuationMessageId: null, workAllowed: true },
      { continuationMessageId: '77'.repeat(16), workAllowed: false },
    ]) {
      const native = vi.fn().mockResolvedValue({
        outcome: 'authorized',
        policyDigest,
        policyName: 'peer-work',
        requestMessageId: '66'.repeat(16),
        attempt: 1,
        ...evidence,
      });
      const gate = createCopilotPolicyGate(client(native));
      if (evidence.continuationMessageId === '77'.repeat(16) && evidence.workAllowed) {
        const decision = await gate.authorizeTurn([answer]);
        expect(decision).toMatchObject(evidence);
        expect(native).toHaveBeenCalledWith('collaboration.turn.authorize', {
          conversationId: conversation,
          requestMessageId: '66'.repeat(16),
          continuationMessageId: '77'.repeat(16),
          notificationId: '01'.repeat(16),
          leaseGeneration: 1,
        });
        if (!decision || 'kind' in decision) {
          throw new Error('expected a continuation authorization');
        }
        gate.activate(decision);
        gate.observePrompt(
          `Konclave delivered 1 update\n${collaborationTurnTokenLabel}: ${decision.turnToken}`,
        );
        expect(
          await gate.hooks.onPreToolUse?.(
            hookInput('send_message', {
              conversation_id: conversation,
              message_id: '88'.repeat(16),
              text: 'ack',
            }),
            { sessionId: 'session' },
          ),
        ).toMatchObject({ permissionDecision: 'deny' });
        native.mockResolvedValue({ decision: 'allow' });
        expect(
          await gate.hooks.onPreToolUse?.(hookInput('view', { path: 'workspace' }), {
            sessionId: 'session',
          }),
        ).not.toHaveProperty('permissionDecision');
        native.mockResolvedValue({ decision: 'deny', reason: 'policy_changed' });
        expect(
          await gate.hooks.onPreToolUse?.(hookInput('view', { path: 'workspace' }), {
            sessionId: 'session',
          }),
        ).toMatchObject({ permissionDecision: 'deny' });
      } else {
        await expect(gate.authorizeTurn([answer])).rejects.toThrow('authorization is malformed');
      }
    }
  });

  it.each([true, false, undefined])(
    'parses explicit native work evidence %j',
    async (workAllowed) => {
      const gate = createCopilotPolicyGate(
        client(
          vi.fn().mockResolvedValue({
            outcome: 'authorized',
            policyDigest,
            policyName: 'not-a-permission',
            requestMessageId: '66'.repeat(16),
            attempt: 1,
            workAllowed,
          }),
        ),
      );
      const decision = await gate.authorizeTurn([requestEvent()]);
      expect(decision).toMatchObject({ policyDigest });
      expect(decision && !('kind' in decision) && decision.workAllowed === true).toBe(
        workAllowed === true,
      );
    },
  );

  it.each([null, 'true', 1, { allowed: true }])(
    'rejects malformed native work evidence %j',
    async (workAllowed) => {
      const gate = createCopilotPolicyGate(
        client(
          vi.fn().mockResolvedValue({
            outcome: 'authorized',
            policyDigest,
            policyName: 'peer-work',
            requestMessageId: '66'.repeat(16),
            attempt: 1,
            workAllowed,
          }),
        ),
      );
      await expect(gate.authorizeTurn([requestEvent()])).rejects.toThrow(
        'peer-work permission is malformed',
      );
    },
  );

  it('admits ordinary work without overriding native permissions or tool arguments', async () => {
    const request = vi.fn().mockResolvedValue({ decision: 'allow', authorization: null });
    const gate = createCopilotPolicyGate(client(request));
    activateGate(gate, true);
    const args = { path: 'workspace' };
    const result = await gate.hooks.onPreToolUse?.(hookInput('view', args), {
      sessionId: 'session',
    });
    expect(result).toEqual({
      additionalContext: expect.stringContaining('normal Copilot permissions'),
    });
    expect(result).not.toHaveProperty('permissionDecision');
    expect(result).not.toHaveProperty('modifiedArgs');
    expect(gate.prepareToolArguments('view', args)).toBe(args);
    expect(request).toHaveBeenCalledWith('collaboration.action.evaluate', {
      conversationId: conversation,
      policyDigest,
      action: 'session.work',
      resource: null,
      requestMessageId: '66'.repeat(16),
      attempt: 1,
    });
  });

  it('permits explicit follow-up requests only in the authorized conversation', async () => {
    const request = vi.fn().mockResolvedValue({ decision: 'allow' });
    const gate = createCopilotPolicyGate(client(request));
    activateGate(gate, true);
    for (const conversation_id of [undefined, 'ff'.repeat(32)]) {
      const denied = await gate.hooks.onPreToolUse?.(
        hookInput('send_directed_request', { conversation_id }),
        { sessionId: 'session' },
      );
      expect(denied).toMatchObject({ permissionDecision: 'deny' });
    }
    expect(request).not.toHaveBeenCalled();
    const args = {
      conversation_id: conversation,
      message_id: '44'.repeat(16),
      text: 'review these changes',
    };
    expect(
      await gate.hooks.onPreToolUse?.(hookInput('send_directed_request', args), {
        sessionId: 'session',
      }),
    ).not.toHaveProperty('permissionDecision');
    expect(request).toHaveBeenCalledTimes(1);
  });

  it.each([
    'accept_collaboration_policy',
    'functions.extensions_reload',
    'provider.collaboration.turn.authorize',
  ])('does not delegate control tool %s even with work permission', async (toolName) => {
    const request = vi.fn();
    const gate = createCopilotPolicyGate(client(request));
    activateGate(gate, true);
    expect(
      await gate.hooks.onPreToolUse?.(hookInput(toolName, {}), { sessionId: 'session' }),
    ).toMatchObject({ permissionDecision: 'deny' });
    expect(request).not.toHaveBeenCalled();
  });

  it.each([
    { decision: 'deny', reason: 'policy_inactive' },
    { decision: 'deny', reason: 'policy_changed' },
    { decision: 'deny', reason: 'directed_request_claim_inactive' },
    { decision: 'ask', reason: 'local_approval_required' },
    { decision: 'allow', authorization: 'aa'.repeat(16) },
    { decision: 'unknown' },
  ])('fails closed for a work evaluation %j', async (decision) => {
    const request = vi.fn().mockResolvedValue(decision);
    const gate = createCopilotPolicyGate(client(request));
    activateGate(gate, true);
    expect(
      await gate.hooks.onPreToolUse?.(hookInput('view', {}), { sessionId: 'session' }),
    ).toMatchObject({ permissionDecision: 'deny' });
  });

  it('fails closed when a native work check becomes unavailable', async () => {
    const gate = createCopilotPolicyGate(client(vi.fn().mockRejectedValue(new Error('offline'))));
    activateGate(gate, true);
    expect(
      await gate.hooks.onPreToolUse?.(hookInput('view', {}), { sessionId: 'session' }),
    ).toMatchObject({ permissionDecision: 'deny' });
    expect(gate.lastDecision).toBe('gate_unavailable');
  });

  it('reports finite work-check diagnostics without exposing the exception content', async () => {
    const error = new Error('private request body and credentials');
    attachLocalFailure(error, { stage: 'client_validation', code: 'invalid_request' });
    const gate = createCopilotPolicyGate(client(vi.fn().mockRejectedValue(error)));
    activateGate(gate, true);
    const decision = await gate.hooks.onPreToolUse?.(hookInput('view', {}), {
      sessionId: 'session',
    });
    expect(decision).toMatchObject({
      permissionDecision: 'deny',
      permissionDecisionReason: expect.stringContaining(
        'stage=client_validation code=invalid_request',
      ),
    });
    expect(JSON.stringify(decision)).not.toContain(error.message);
    expect(gate.lastDecision).toBe('gate_unavailable');
  });

  it.each(['foreground', 'clear', 'replacement'])(
    'rejects in-flight work when %s changes the turn',
    async (transition) => {
      let resolveEvaluation: (value: unknown) => void = () => {
        throw new Error('evaluation not started');
      };
      const request = vi.fn(
        () =>
          new Promise<unknown>((resolve) => {
            resolveEvaluation = resolve;
          }),
      );
      const gate = createCopilotPolicyGate(client(request));
      activateGate(gate, true);
      const result = gate.hooks.onPreToolUse?.(hookInput('view', {}), { sessionId: 'session' });
      expect(request).toHaveBeenCalledTimes(1);
      if (transition === 'foreground') {
        gate.observePrompt('a new local user request');
      } else if (transition === 'clear') {
        gate.clear();
      } else {
        activateGate(gate, true);
      }
      resolveEvaluation({ decision: 'allow' });
      expect(await result).toMatchObject({ permissionDecision: 'deny' });
      expect(gate.lastDecision).toBe('turn_changed');
    },
  );

  it('preserves the exact reply authorization path during working turns', async () => {
    const gate = createCopilotPolicyGate(
      client(
        vi.fn().mockResolvedValue({
          decision: 'allow',
          authorization: 'aa'.repeat(16),
        }),
      ),
    );
    activateGate(gate, true);
    const result = await gate.hooks.onPreToolUse?.(
      hookInput('send_message', {
        conversation_id: conversation,
        message_id: '44'.repeat(16),
        text: 'work completed',
      }),
      { sessionId: 'session' },
    );
    expect(gate.prepareToolArguments('send_message', result?.modifiedArgs)).toMatchObject({
      collaboration_authorization: 'aa'.repeat(16),
      reply_to_message_id: '66'.repeat(16),
    });
  });

  it('keeps terminal delivery out of model turns', async () => {
    const request = vi.fn();
    const gate = createCopilotPolicyGate(client(request));
    const channelRequest = vi.fn().mockResolvedValue({ kind: 'accepted' });
    const send = vi.fn();
    const error = vi.fn();
    const delivery = createDeliveryCoordinator({
      channel: {
        profile: 'session-policy-gate',
        request: channelRequest,
        close() {},
      },
      session: { send },
      diagnostics: { error },
      authorizeTurn: (events) => gate.authorizeTurn(events),
      completeAuthorizedTurn: (authorization) => gate.completeTurn(authorization),
      canCompleteAuthorizedTurn: (authorization) => gate.canCompleteTurn(authorization),
      activateAuthorizedTurn: (authorization) => gate.activate(authorization),
      clearAuthorizedTurn: () => gate.clear(),
    });

    delivery.enqueue([event()]);
    await delivery.markIdle();

    expect(gate.active).toBe(false);
    expect(send).not.toHaveBeenCalled();
    expect(request).not.toHaveBeenCalled();
    expect(channelRequest).toHaveBeenCalledWith({
      kind: 'acknowledge',
      notificationId: event().notificationId,
      leaseGeneration: 1,
    });
    expect(error).toHaveBeenCalledWith(
      'Konclave retained a terminal update in message history; no automatic turn was started.',
    );
  });

  it('does not infer an automatic request from ordinary application text', async () => {
    const request = vi.fn();
    const gate = createCopilotPolicyGate(client(request));

    await expect(gate.authorizeTurn([event()])).resolves.toBeNull();
    expect(request).not.toHaveBeenCalled();
  });

  it('binds exact directed request authorization and completion fields', async () => {
    const request = vi.fn(async (operation: string) => {
      if (operation === 'collaboration.turn.authorize') {
        return {
          outcome: 'authorized',
          reason: null,
          policyDigest,
          policyName: 'contract-alignment',
          requestMessageId: '66'.repeat(16),
          attempt: 2,
        };
      }
      if (operation === 'collaboration.turn.complete') {
        return { outcome: 'completed_no_response', changed: true };
      }
      throw new Error(`unexpected operation: ${operation}`);
    });
    const gate = createCopilotPolicyGate(client(request));
    const authorization = await gate.authorizeTurn([requestEvent()]);

    expect(authorization).toEqual({
      conversation,
      policyDigest,
      policyName: 'contract-alignment',
      requestMessageId: '66'.repeat(16),
      attempt: 2,
      turnToken: expect.stringMatching(/^[0-9a-f]{32}$/u),
    });
    expect(request).toHaveBeenCalledWith('collaboration.turn.authorize', {
      conversationId: conversation,
      requestMessageId: '66'.repeat(16),
      notificationId: '01'.repeat(16),
      leaseGeneration: 1,
    });
    if (!authorization || 'kind' in authorization) {
      throw new Error('directed request was not authorized');
    }
    await expect(gate.completeTurn(authorization)).resolves.toBe('completed-no-response');
    expect(request).toHaveBeenCalledWith('collaboration.turn.complete', {
      conversationId: conversation,
      policyDigest,
      requestMessageId: '66'.repeat(16),
      attempt: 2,
    });
  });

  it('waits for the exact synthetic prompt before allowing idle completion', () => {
    const gate = createCopilotPolicyGate(client(vi.fn()));
    const authorization = {
      conversation,
      policyDigest,
      policyName: 'contract-alignment',
      requestMessageId: '66'.repeat(16),
      attempt: 1,
      turnToken: '77'.repeat(16),
    };
    gate.activate(authorization);
    expect(gate.canCompleteTurn(authorization)).toBe(false);

    gate.observePrompt('foreground user prompt');
    expect(gate.canCompleteTurn(authorization)).toBe(false);
    gate.observePrompt(
      `Konclave delivered 1 update\n${collaborationTurnTokenLabel}: ${authorization.turnToken}`,
    );
    expect(gate.canCompleteTurn(authorization)).toBe(true);
    expect(gate.active).toBe(true);
    gate.clear();
    expect(gate.canCompleteTurn(authorization)).toBe(false);
  });

  it('fails closed if another prompt arrives before the authorized turn becomes idle', async () => {
    const request = vi.fn();
    const gate = createCopilotPolicyGate(client(request));
    const authorization = {
      conversation,
      policyDigest,
      policyName: 'contract-alignment',
      requestMessageId: '66'.repeat(16),
      attempt: 1,
      turnToken: '78'.repeat(16),
    };
    gate.activate(authorization);
    gate.observePrompt(
      `Konclave delivered 1 update\n${collaborationTurnTokenLabel}: ${authorization.turnToken}`,
    );

    gate.observePrompt('foreground user prompt');

    expect(gate.active).toBe(true);
    expect(gate.canCompleteTurn(authorization)).toBe(true);
    await expect(
      gate.hooks.onPreToolUse?.(
        hookInput('send_message', {
          conversation_id: conversation,
          message_id: '44'.repeat(16),
          text: 'must not escape the turn gate',
        }),
        { sessionId: 'session' },
      ),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
    expect(gate.lastDecision).toBe('delayed_prompt_unbound');
    expect(request).not.toHaveBeenCalled();
  });

  it('fails closed when an active authorization prompt is replayed', async () => {
    const request = vi.fn();
    const gate = createCopilotPolicyGate(client(request));
    const turnToken = '79'.repeat(16);
    gate.activate({
      conversation,
      policyDigest,
      policyName: 'contract-alignment',
      requestMessageId: '66'.repeat(16),
      attempt: 1,
      turnToken,
    });
    const prompt = `Konclave delivered 1 update\n${collaborationTurnTokenLabel}: ${turnToken}`;
    gate.observePrompt(prompt);
    gate.observePrompt(prompt);

    await expect(
      gate.hooks.onPreToolUse?.(
        hookInput('send_message', {
          conversation_id: conversation,
          message_id: '44'.repeat(16),
          text: 'must not use a replayed authorization',
        }),
        { sessionId: 'session' },
      ),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
    expect(gate.lastDecision).toBe('delayed_prompt_unbound');
    expect(request).not.toHaveBeenCalled();
  });

  it('blocks a stale Konclave prompt while another authorization is pending', async () => {
    const request = vi.fn();
    const gate = createCopilotPolicyGate(client(request));
    const authorization = {
      conversation,
      policyDigest,
      policyName: 'contract-alignment',
      requestMessageId: '66'.repeat(16),
      attempt: 1,
      turnToken: '7a'.repeat(16),
    };
    gate.activate(authorization);
    gate.observePrompt(
      `Konclave delivered 1 update\n${collaborationTurnTokenLabel}: ${'7b'.repeat(16)}`,
    );

    expect(gate.active).toBe(true);
    expect(gate.canCompleteTurn(authorization)).toBe(false);
    await expect(
      gate.hooks.onPreToolUse?.(
        hookInput('send_message', {
          conversation_id: conversation,
          message_id: '44'.repeat(16),
          text: 'must not use a stale prompt',
        }),
        { sessionId: 'session' },
      ),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
    expect(gate.lastDecision).toBe('delayed_prompt_unbound');
    expect(request).not.toHaveBeenCalled();
  });

  it('defers a request while another live handling claim owns it', async () => {
    const gate = createCopilotPolicyGate(
      client(
        vi.fn().mockResolvedValue({
          outcome: 'denied',
          reason: 'directed_request_claimed',
        }),
      ),
    );

    await expect(gate.authorizeTurn([requestEvent()])).resolves.toEqual({
      kind: 'deferred',
    });
  });

  it('maps supported tools while preserving native permission checks', async () => {
    const request = vi
      .fn()
      .mockResolvedValue({ decision: 'allow', reason: null, authorization: 'aa'.repeat(16) });
    const gate = createCopilotPolicyGate(client(request));
    activateGate(gate);

    const response = await gate.hooks.onPreToolUse?.(
      hookInput('send_message', {
        conversation_id: conversation,
        message_id: '44'.repeat(16),
        reply_to_message_id: '66'.repeat(16),
        text: 'reply',
      }),
      { sessionId: 'session' },
    );

    expect(response).toEqual({
      modifiedArgs: {
        conversation_id: conversation,
        message_id: '44'.repeat(16),
        reply_to_message_id: '66'.repeat(16),
        text: 'reply',
      },
      additionalContext:
        'Konclave policy permits this action, but normal Copilot permissions still apply.',
    });
    expect(gate.lastDecision).toBe('authorized');
    expect(request).toHaveBeenCalledWith('collaboration.action.evaluate', {
      conversationId: conversation,
      policyDigest,
      action: 'conversation.reply',
      resource: null,
      messageId: '44'.repeat(16),
      replyToMessageId: '66'.repeat(16),
      text: 'reply',
      requestMessageId: '66'.repeat(16),
      attempt: 1,
    });
    expect(gate.prepareToolArguments('send_message', response?.modifiedArgs)).toEqual({
      conversation_id: conversation,
      message_id: '44'.repeat(16),
      reply_to_message_id: '66'.repeat(16),
      text: 'reply',
      collaboration_authorization: 'aa'.repeat(16),
    });
    expect(() => gate.prepareToolArguments('send_message', response?.modifiedArgs)).toThrow(
      'authorization is unavailable',
    );

    const encodedResponse = await gate.hooks.onPreToolUse?.(
      hookInput(
        'functions.send_message',
        JSON.stringify({
          conversation_id: conversation,
          message_id: '45'.repeat(16),
          reply_to_message_id: '66'.repeat(16),
          text: 'encoded reply',
        }),
      ),
      { sessionId: 'session' },
    );
    expect(encodedResponse).toMatchObject({
      modifiedArgs: {
        conversation_id: conversation,
        message_id: '45'.repeat(16),
        reply_to_message_id: '66'.repeat(16),
        text: 'encoded reply',
      },
    });
    expect(gate.lastDecision).toBe('authorized');
    expect(
      gate.prepareToolArguments('functions.send_message', encodedResponse?.modifiedArgs),
    ).toEqual({
      conversation_id: conversation,
      message_id: '45'.repeat(16),
      reply_to_message_id: '66'.repeat(16),
      text: 'encoded reply',
      collaboration_authorization: 'aa'.repeat(16),
    });

    const changedResponse = await gate.hooks.onPreToolUse?.(
      hookInput('send_message', {
        conversation_id: conversation,
        message_id: '46'.repeat(16),
        reply_to_message_id: '66'.repeat(16),
        text: 'authorized text',
      }),
      { sessionId: 'session' },
    );
    const changedArguments = changedResponse?.modifiedArgs;
    if (
      typeof changedArguments !== 'object' ||
      changedArguments === null ||
      Array.isArray(changedArguments)
    ) {
      throw new Error('authorized send arguments were not returned');
    }
    expect(() =>
      gate.prepareToolArguments('send_message', {
        ...changedArguments,
        text: 'changed text',
      }),
    ).toThrow('arguments changed after authorization');
    gate.clear();
    activateGate(gate);

    const lifecycleResponse = await gate.hooks.onPreToolUse?.(
      hookInput('send_message', {
        conversation_id: conversation,
        message_id: '47'.repeat(16),
        reply_to_message_id: '66'.repeat(16),
        text: 'lifecycle reply',
      }),
      { sessionId: 'session' },
    );
    gate.observePrompt('foreground user prompt');
    expect(() =>
      gate.prepareToolArguments('send_message', lifecycleResponse?.modifiedArgs),
    ).toThrow('turn changed after authorization');
    gate.clear();
    activateGate(gate);

    const callerSuppliedAuthorization = await gate.hooks.onPreToolUse?.(
      hookInput('send_message', {
        conversation_id: conversation,
        message_id: '48'.repeat(16),
        reply_to_message_id: '66'.repeat(16),
        text: 'reply',
        [collaborationAuthorizationArgument]: '33'.repeat(16),
      }),
      { sessionId: 'session' },
    );
    expect(callerSuppliedAuthorization).toMatchObject({
      modifiedArgs: {
        conversation_id: conversation,
        message_id: '48'.repeat(16),
        reply_to_message_id: '66'.repeat(16),
        text: 'reply',
      },
    });
    expect(callerSuppliedAuthorization?.modifiedArgs).not.toHaveProperty(
      collaborationAuthorizationArgument,
    );
    expect(
      gate.prepareToolArguments('send_message', callerSuppliedAuthorization?.modifiedArgs),
    ).toEqual({
      conversation_id: conversation,
      message_id: '48'.repeat(16),
      reply_to_message_id: '66'.repeat(16),
      text: 'reply',
      collaboration_authorization: 'aa'.repeat(16),
    });

    expect(
      gate.prepareToolArguments('get_identity', {
        conversation_id: conversation,
      }),
    ).toEqual({ conversation_id: conversation });

    await expect(
      gate.hooks.onPreToolUse?.(
        hookInput(
          'send_message',
          JSON.stringify({
            conversation_id: conversation,
            message_id: '49'.repeat(16),
            text: 'reply',
            unexpected: true,
          }),
        ),
        { sessionId: 'session' },
      ),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
    expect(gate.lastDecision).toBe('send_arguments_malformed');
  });

  it('rejects malformed, scalar, collection, and oversized serialized arguments', async () => {
    const request = vi.fn();
    const gate = createCopilotPolicyGate(client(request));
    activateGate(gate);

    for (const toolArgs of [
      'not-json',
      'null',
      '[]',
      JSON.stringify({
        conversation_id: conversation,
        message_id: '47'.repeat(16),
        text: 'reply',
        unexpected: true,
      }),
      JSON.stringify({
        conversation_id: conversation,
        message_id: 'invalid',
        text: 'reply',
      }),
      JSON.stringify({
        conversation_id: conversation,
        message_id: '48'.repeat(16),
        text: 'x'.repeat(64 * 1024 + 1),
      }),
      'x'.repeat(128 * 1024 + 1),
      new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error('unexpected proxy access');
          },
        },
      ),
    ]) {
      await expect(
        gate.hooks.onPreToolUse?.(hookInput('send_message', toolArgs), {
          sessionId: 'session',
        }),
      ).resolves.toMatchObject({ permissionDecision: 'deny' });
    }
    expect(gate.lastDecision).toBe('gate_unavailable');
    expect(request).not.toHaveBeenCalled();
  });

  it('binds conversation tools and fails closed for unknown or unavailable decisions', async () => {
    const request = vi
      .fn()
      .mockResolvedValue({ decision: 'allow', reason: null, authorization: 'aa'.repeat(16) });
    const gate = createCopilotPolicyGate(client(request));
    activateGate(gate);

    await expect(
      gate.hooks.onPreToolUse?.(hookInput('send_message', { conversation_id: '33'.repeat(32) }), {
        sessionId: 'session',
      }),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
    expect(gate.lastDecision).toBe('conversation_mismatch');
    await expect(
      gate.hooks.onPreToolUse?.(hookInput('unknown_tool', {}), { sessionId: 'session' }),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
    expect(gate.lastDecision).toBe('tool_unmapped');
    expect(request).not.toHaveBeenCalled();

    await expect(
      gate.hooks.onPreToolUse?.(
        {
          ...hookInput('send_message', {
            conversation_id: conversation,
            message_id: '66'.repeat(16),
            text: 'reply',
          }),
          sessionId: 'descendant-session',
        },
        { sessionId: 'session' },
      ),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
    expect(gate.lastDecision).toBe('descendant_session');
    expect(request).not.toHaveBeenCalled();

    request.mockResolvedValueOnce({ decision: 'ask', reason: 'local_approval_required' });
    await expect(
      gate.hooks.onPreToolUse?.(
        hookInput('send_message', {
          conversation_id: conversation,
          message_id: '67'.repeat(16),
          text: 'reply',
        }),
        { sessionId: 'session' },
      ),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });

    request.mockResolvedValueOnce({ decision: 'deny', reason: 'policy_denied' });
    await expect(
      gate.hooks.onPreToolUse?.(
        hookInput('send_message', {
          conversation_id: conversation,
          message_id: '68'.repeat(16),
          text: 'reply',
        }),
        { sessionId: 'session' },
      ),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });

    request.mockRejectedValueOnce(new Error('service unavailable'));
    await expect(
      gate.hooks.onPreToolUse?.(
        hookInput('send_message', {
          conversation_id: conversation,
          message_id: '69'.repeat(16),
          text: 'reply',
        }),
        { sessionId: 'session' },
      ),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
  });
});
