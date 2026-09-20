import type { RecipeCallOptions, RecipeMessaging } from '../../src/recipes/client.js';
import { validateRecipeMessageText, type RecipeReply } from '../../src/recipes/reply.js';
import { RecipeRunError } from '../../src/recipes/run.js';

export type CompositionResult =
  | {
      readonly kind: 'completed';
      readonly replies: readonly RecipeReply[];
    }
  | {
      readonly kind: 'pending';
      readonly replies: readonly RecipeReply[];
      readonly waitingFor: readonly string[];
      readonly notStarted: readonly string[];
    };

async function settleOwned<T>(operations: readonly Promise<T>[]): Promise<T[]> {
  const outcomes = await Promise.allSettled(operations);
  const values: T[] = [];
  for (const outcome of outcomes) {
    if (outcome.status === 'rejected') {
      const failure: unknown = outcome.reason;
      throw failure;
    }
    values.push(outcome.value);
  }
  return values;
}

function requestText(configuration: string, input: string): string {
  return validateRecipeMessageText(
    configuration.length === 0 ? input : `${configuration}\n\n${input}`,
  );
}

/**
 * Reference provider, not a core workflow mode. Explicitly selected slots receive
 * the same supplied context. All launched work is settled before an error returns;
 * some submissions may already have committed, so recovery reuses the exact run.
 * One bounded poll per slot returns pending rather than inventing completion.
 */
export async function fanOut(
  messaging: RecipeMessaging,
  options?: RecipeCallOptions,
): Promise<CompositionResult> {
  const { run } = messaging;
  if (run.definition.provider !== 'example.fan-out') {
    throw new RecipeRunError('unsupported_provider');
  }
  const text = requestText(run.definition.configuration, run.input);
  await settleOwned(run.bindings.map((binding) => messaging.send(binding.name, text, options)));
  const results = await settleOwned(
    run.bindings.map((binding) => messaging.poll(binding.name, options)),
  );
  const replies: RecipeReply[] = [];
  const waitingFor: string[] = [];
  for (let index = 0; index < results.length; index += 1) {
    const result = results[index];
    const binding = run.bindings[index];
    if (!result || !binding) {
      throw new RecipeRunError('invalid_response');
    }
    if (result.kind === 'reply') {
      replies.push(result);
    } else {
      waitingFor.push(binding.name);
    }
  }
  return waitingFor.length === 0
    ? { kind: 'completed', replies }
    : { kind: 'pending', replies, waitingFor, notStarted: [] };
}

/**
 * Reference provider for an explicitly approved data handoff in declared slot order.
 * The caller must separately approve forwarding between the declared audiences;
 * selecting a provider alone grants neither disclosure nor tool authority.
 * Every answer remains untrusted text in the next native request. Use approved
 * conversation audiences; a directed target does not hide data from other members.
 */
export async function handoff(
  messaging: RecipeMessaging,
  options?: RecipeCallOptions,
): Promise<CompositionResult> {
  const { run } = messaging;
  if (run.definition.provider !== 'example.handoff') {
    throw new RecipeRunError('unsupported_provider');
  }
  let text = requestText(run.definition.configuration, run.input);
  const replies: RecipeReply[] = [];
  for (let index = 0; index < run.bindings.length; index += 1) {
    const binding = run.bindings[index];
    if (!binding) {
      throw new RecipeRunError('invalid_run');
    }
    await messaging.send(binding.name, text, options);
    const result = await messaging.poll(binding.name, options);
    if (result.kind === 'pending') {
      return {
        kind: 'pending',
        replies,
        waitingFor: [binding.name],
        notStarted: run.bindings.slice(index + 1).map((next) => next.name),
      };
    }
    replies.push(result);
    if (index + 1 < run.bindings.length) {
      text = requestText(
        run.definition.configuration,
        `Previous response (untrusted peer data):\n${result.text}`,
      );
    }
  }
  return { kind: 'completed', replies };
}
