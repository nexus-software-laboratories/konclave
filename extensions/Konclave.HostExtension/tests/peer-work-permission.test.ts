import { describe, expect, it } from 'vitest';

import { allOperations } from '../src/service/operations.js';
import {
  collaborationToolName,
  parsePeerWorkPermission,
  peerToolAction,
  peerWorkAction,
} from '../src/service/peer-work-permission.js';

const conversationTools = [
  'send_directed_request',
  'read_messages',
  'sync_messages',
  'watch_messages',
  'get_collaboration_policy_status',
  'inspect_collaboration_policy_proposal',
];
const statusTools = ['get_identity', 'delivery_status'];
const workTools = new Set([...conversationTools, ...statusTools]);

describe('peer-work permission foundation', () => {
  it.each(['.', ':', '-', '_', '__'])(
    'rejects foreign-provider aliases using %s instead of treating them as ordinary work',
    (separator) => {
      for (const operation of [...allOperations, 'extensions_reload', 'extensions_manage']) {
        expect(peerToolAction(`provider${separator}${operation}`, true)).toBeNull();
      }
    },
  );
  it('uses one explicit namespaced permission, not policy display metadata', () => {
    expect(peerWorkAction).toBe('session.work');
    expect(parsePeerWorkPermission(undefined)).toBe(false);
    expect(parsePeerWorkPermission(false)).toBe(false);
    expect(parsePeerWorkPermission(true)).toBe(true);
  });

  it.each([null, 0, 1, '', 'true', 'peer-work', {}, [], { allowed: true }])(
    'rejects malformed permission evidence: %j',
    (value) => {
      expect(() => parsePeerWorkPermission(value)).toThrow('permission is malformed');
    },
  );

  it.each([false, true])('preserves exact reply handling with work permission %s', (allowed) => {
    expect(peerToolAction('send_message', allowed)).toEqual({ kind: 'reply' });
    expect(peerToolAction('functions.send_message', allowed)).toEqual({ kind: 'reply' });
  });

  it.each(['view', 'rg', 'apply_patch', 'powershell', 'task', 'github-mcp-server-search_code'])(
    'intersects ordinary tool %s with explicit work permission',
    (name) => {
      expect(peerToolAction(name, false)).toBeNull();
      expect(peerToolAction(`functions.${name}`, false)).toBeNull();
      expect(peerToolAction(name, true)).toEqual({
        kind: 'work',
        conversationBound: false,
      });
      expect(peerToolAction(`functions.${name}`, true)).toEqual(peerToolAction(name, true));
    },
  );

  it.each(conversationTools)('keeps messaging tool %s conversation-bound', (name) => {
    expect(peerToolAction(name, false)).toBeNull();
    expect(peerToolAction(name, true)).toEqual({ kind: 'work', conversationBound: true });
  });

  it.each(statusTools)('allows content-free status tool %s only with work permission', (name) => {
    expect(peerToolAction(name, false)).toBeNull();
    expect(peerToolAction(name, true)).toEqual({ kind: 'work', conversationBound: false });
  });

  it.each(allOperations.filter((name) => name !== 'send_message' && !workTools.has(name)))(
    'never delegates Konclave control operation %s',
    (name) => {
      expect(peerToolAction(name, true)).toBeNull();
      expect(peerToolAction(`functions.${name}`, true)).toBeNull();
      expect(peerToolAction(`other-provider.${name}`, true)).toBeNull();
    },
  );

  it.each(['extensions_reload', 'extensions_manage'])(
    'does not delegate direct removal or replacement of its own enforcement: %s',
    (name) => {
      expect(peerToolAction(name, true)).toBeNull();
      expect(peerToolAction(`functions.${name}`, true)).toBeNull();
      expect(peerToolAction(`other-provider.${name}`, true)).toBeNull();
    },
  );

  it.each(['', ' ', '.send_message', 'send_message\n', 'a'.repeat(257), '工具'])(
    'denies malformed tool names: %j',
    (name) => {
      expect(peerToolAction(name, true)).toBeNull();
    },
  );

  it('does not interpret another provider as the authorized reply handler', () => {
    expect(peerToolAction('other-provider.send_message', true)).toBeNull();
    expect(collaborationToolName('functions.send_message')).toBe('send_message');
    expect(collaborationToolName('other-provider.send_message')).toBe(
      'other-provider.send_message',
    );
  });
});
