import { joinSession } from '@github/copilot-sdk/extension';

const discoveredTool = {
  name: 'konclave_sdk_proxy_probe',
  description: 'Return one value through an extension-owned dynamic tool handler.',
  parameters: {
    type: 'object',
    properties: {
      value: { type: 'string' },
    },
    required: ['value'],
    additionalProperties: false,
  },
};

await joinSession({
  tools: [
    {
      ...discoveredTool,
      handler: async ({ value }) => ({
        source: 'extension-owned-handler',
        value,
      }),
    },
  ],
});
