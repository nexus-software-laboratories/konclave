import { describe, expect, it, vi } from 'vitest';

import { createDeliveryCoordinator } from '../src/adapter/delivery.js';
import type { DeliveredEvent } from '../src/adapter/session.js';
import type { LocalServiceClient } from '../src/service/client.js';
import {
  createCopilotPolicyGate,
  type CopilotPolicyGate,
} from '../src/service/policy-enforcement.js';

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

function activateGate(gate: CopilotPolicyGate): void {
  const turnToken = '33'.repeat(16);
  gate.activate({
    conversation,
    policyDigest,
    policyName: 'contract-alignment',
    requestMessageId: '66'.repeat(16),
    attempt: 1,
    turnToken,
  });
  gate.observePrompt(
    `Konclave delivered 1 update\nKonclave collaboration authorization token: ${turnToken}`,
  );
}

describe('Copilot collaboration policy gate', () => {
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
      `Konclave delivered 1 update\nKonclave collaboration authorization token: ${authorization.turnToken}`,
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
      `Konclave delivered 1 update\nKonclave collaboration authorization token: ${authorization.turnToken}`,
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
    const prompt = `Konclave delivered 1 update\nKonclave collaboration authorization token: ${turnToken}`;
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
      `Konclave delivered 1 update\nKonclave collaboration authorization token: ${'7b'.repeat(16)}`,
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
        collaboration_authorization: 'aa'.repeat(16),
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
        collaboration_authorization: 'aa'.repeat(16),
      },
    });
    expect(gate.lastDecision).toBe('authorized');

    await expect(
      gate.hooks.onPreToolUse?.(
        hookInput(
          'send_message',
          JSON.stringify({
            conversation_id: conversation,
            message_id: '46'.repeat(16),
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
