export function isMemoryContextMessage(data: unknown): boolean {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return false;
  }
  return (
    'source' in data &&
    data.source === 'memory' &&
    'content' in data &&
    data.content === '' &&
    'transformedContent' in data &&
    typeof data.transformedContent === 'string' &&
    data.transformedContent.length > 0 &&
    !('messageId' in data)
  );
}
