import { allOperations } from './operations.js';

export const peerWorkAction = 'session.work';

export type PeerToolAction =
  { readonly kind: 'reply' } | { readonly kind: 'work'; readonly conversationBound: boolean };

const conversationTools = new Set([
  'send_directed_request',
  'read_messages',
  'sync_messages',
  'watch_messages',
  'get_collaboration_policy_status',
  'inspect_collaboration_policy_proposal',
]);
const statusTools = new Set(['get_identity', 'delivery_status']);
const extensionControlTools = new Set(['extensions_reload', 'extensions_manage']);

export function collaborationToolName(toolName: string): string {
  return toolName.startsWith('functions.') ? toolName.slice('functions.'.length) : toolName;
}

export function parsePeerWorkPermission(value: unknown): boolean {
  if (value === undefined) {
    return false;
  }
  if (typeof value !== 'boolean') {
    throw new Error('the local service peer-work permission is malformed');
  }
  return value;
}

export function peerToolAction(toolName: string, workAllowed: boolean): PeerToolAction | null {
  const name = collaborationToolName(toolName);
  if (!/^[a-zA-Z_][a-zA-Z0-9_.:-]{0,255}$/u.test(name)) {
    return null;
  }
  if (name === 'send_message') {
    return { kind: 'reply' };
  }
  if (workAllowed !== true || extensionControlTools.has(name)) {
    return null;
  }
  if (conversationTools.has(name)) {
    return { kind: 'work', conversationBound: true };
  }
  if (statusTools.has(name)) {
    return { kind: 'work', conversationBound: false };
  }
  if (
    allOperations.some((operation) => name === operation || name.endsWith(`.${operation}`)) ||
    [...extensionControlTools].some((operation) => name.endsWith(`.${operation}`))
  ) {
    return null;
  }
  return { kind: 'work', conversationBound: false };
}
