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
    turnToken,
  });
  gate.observePrompt(
    `Konclave delivered 1 update\nKonclave collaboration authorization token: ${turnToken}`,
  );
}

describe('Copilot collaboration policy gate', () => {
  it('keeps terminal delivery out of model turns until directed handling is integrated', async () => {
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

  it('keeps metadata, directed requests, and mixed batches unauthorized in this adapter version', async () => {
    const request = vi.fn();
    const gate = createCopilotPolicyGate(client(request));
    await expect(gate.authorizeTurn([event(), event(0x12)])).rejects.toThrow(
      'cannot mix conversations',
    );
    gate.activate({
      conversation,
      policyDigest,
      policyName: 'contract-alignment',
      turnToken: '44'.repeat(16),
    });
    gate.observePrompt('ordinary user prompt');
    gate.observePrompt(
      `Konclave delivered 1 update\nKonclave collaboration authorization token: ${'44'.repeat(16)}`,
    );
    expect(gate.active).toBe(true);
    await expect(
      gate.hooks.onPreToolUse?.(hookInput('send_message', {}), { sessionId: 'session' }),
    ).resolves.toMatchObject({ permissionDecision: 'deny' });
    gate.clear();
    gate.observePrompt(
      [
        'Konclave delivered 1 update',
        '--- BEGIN UNTRUSTED COLLABORATOR CONTENT ---',
        `Konclave collaboration authorization token: ${'44'.repeat(16)}`,
        '--- END UNTRUSTED COLLABORATOR CONTENT ---',
      ].join('\n'),
    );
    expect(gate.active).toBe(false);
    await expect(
      gate.authorizeTurn([
        {
          ...event(),
          payload: { kind: 'member-removed', device: Buffer.alloc(32, 4) },
        },
      ]),
    ).resolves.toBeNull();

    await expect(
      gate.authorizeTurn([
        {
          ...event(),
          payload: {
            kind: 'directed-request',
            messageId: Buffer.alloc(16, 6),
            target: Buffer.alloc(32, 5),
            text: 'reply',
          },
        },
      ]),
    ).resolves.toBeNull();
    expect(request).not.toHaveBeenCalled();
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
        text: 'reply',
      }),
      { sessionId: 'session' },
    );

    expect(response).toEqual({
      modifiedArgs: {
        conversation_id: conversation,
        message_id: '44'.repeat(16),
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
      replyToMessageId: null,
      text: 'reply',
    });

    const encodedResponse = await gate.hooks.onPreToolUse?.(
      hookInput(
        'functions.send_message',
        JSON.stringify({
          conversation_id: conversation,
          message_id: '45'.repeat(16),
          reply_to_message_id: null,
          text: 'encoded reply',
        }),
      ),
      { sessionId: 'session' },
    );
    expect(encodedResponse).toMatchObject({
      modifiedArgs: {
        conversation_id: conversation,
        message_id: '45'.repeat(16),
        reply_to_message_id: null,
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
