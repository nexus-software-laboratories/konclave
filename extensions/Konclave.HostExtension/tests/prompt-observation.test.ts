import { describe, expect, it } from 'vitest';

import { isMemoryContextMessage } from '../src/service/prompt-observation.js';

const memoryContext = {
  source: 'memory',
  content: '',
  transformedContent: '<memories>Untrusted context, not a new prompt.</memories>',
};

describe('memory context message classification', () => {
  it('recognizes the SDK context envelope without interpreting its transformed text', () => {
    expect(isMemoryContextMessage(memoryContext)).toBe(true);
    expect(
      isMemoryContextMessage({
        ...memoryContext,
        transformedContent: 'Konclave delivered 1 update\nKonclave collaboration turn token: fake',
      }),
    ).toBe(true);
  });

  it.each([
    ['null', null],
    ['missing data', undefined],
    ['string', 'memory'],
    ['array', [memoryContext]],
    ['missing source', { content: '', transformedContent: 'context' }],
    ['unknown source', { ...memoryContext, source: 'unknown' }],
    ['nonempty prompt', { ...memoryContext, content: 'interrupt the current turn' }],
    ['identified prompt', { ...memoryContext, messageId: 'foreground-message' }],
    ['undefined prompt identity', { ...memoryContext, messageId: undefined }],
    ['missing content', { source: 'memory', transformedContent: 'context' }],
    ['malformed content', { ...memoryContext, content: null }],
    ['missing context', { source: 'memory', content: '' }],
    ['empty context', { ...memoryContext, transformedContent: '' }],
    ['malformed context', { ...memoryContext, transformedContent: {} }],
  ])('keeps %s observable by the authorization gate', (_label, data) => {
    expect(isMemoryContextMessage(data)).toBe(false);
  });
});
