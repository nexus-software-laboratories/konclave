import { context, trace } from '@opentelemetry/api';
import { getWebAutoInstrumentations } from '@opentelemetry/auto-instrumentations-web';
import { ZoneContextManager } from '@opentelemetry/context-zone';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import {
  BatchSpanProcessor,
  ConsoleSpanExporter,
  SimpleSpanProcessor,
  WebTracerProvider,
} from '@opentelemetry/sdk-trace-web';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { registerInstrumentations } from '@opentelemetry/instrumentation';

// ─── Toggles ──────────────────────────────────────────────────────────────────
//
// These are the knobs you'll most often want to adjust. Defaults are tuned for
// "useful production telemetry"; flip the document-load toggle to silence the
// dev-mode console fan-out (Vite serves every import as a separate HTTP request,
// which produces 30–100+ resourceFetch spans per page load — useless data in
// dev, valuable in production where Vite ships a 1–2 file bundle and you get
// 5–10 spans that actually describe page-load performance).
//
// Override via Vite env var:
//   VITE_OTEL_DOCUMENT_LOAD=false npm run dev
const enableDocumentLoad = import.meta.env.VITE_OTEL_DOCUMENT_LOAD !== 'false';

const serviceName =
  (import.meta.env.VITE_SERVICE_NAME as string | undefined) ?? 'konclave-admin-console';
const otlpEndpoint = import.meta.env.VITE_OTLP_ENDPOINT as string | undefined;
const deploymentEnvironment =
  (import.meta.env.VITE_DEPLOYMENT_ENVIRONMENT as string | undefined) ??
  (import.meta.env.PROD ? 'production' : 'development');

const provider = new WebTracerProvider({
  resource: resourceFromAttributes({
    [ATTR_SERVICE_NAME]: serviceName,
    [ATTR_SERVICE_VERSION]: (import.meta.env.VITE_SERVICE_VERSION as string | undefined) ?? 'dev',
    'deployment.environment': deploymentEnvironment,
  }),
  spanProcessors: otlpEndpoint
    ? [
        new BatchSpanProcessor(
          // Vite environment values are public browser configuration. Route
          // authenticated telemetry through a same-origin server-side proxy.
          new OTLPTraceExporter({
            url: otlpEndpoint.replace(/\/$/, '') + '/v1/traces',
          }),
        ),
      ]
    : // Dev: log spans to the browser console rather than attempting an OTLP
      // round-trip to a CORS-restricted endpoint. The Aspire Dashboard is the
      // primary observability surface in dev — server-side spans still trace
      // the API and Admin requests originated from this app.
      [new SimpleSpanProcessor(new ConsoleSpanExporter())],
});

provider.register({
  // ZoneContextManager makes the active span flow across asynchronous boundaries
  // (Promises, setTimeout, event listeners) without callers having to thread it
  // manually. Required for fetch/xhr instrumentations to attach to user activity.
  contextManager: new ZoneContextManager(),
});

registerInstrumentations({
  instrumentations: [
    getWebAutoInstrumentations({
      // documentLoad fans out one resourceFetch span per module the browser pulls.
      // In Vite dev that means 30–100+ spans per page; in production it's ~5–10.
      // See the toggle comment at the top of this file.
      '@opentelemetry/instrumentation-document-load': {
        enabled: enableDocumentLoad,
      },
      // Propagate W3C traceparent on outbound fetch + xhr requests so server-side
      // spans (in API/Admin) become children of the browser-originated trace.
      '@opentelemetry/instrumentation-fetch': {
        propagateTraceHeaderCorsUrls: [/.+/],
      },
      '@opentelemetry/instrumentation-xml-http-request': {
        propagateTraceHeaderCorsUrls: [/.+/],
      },
      // user-interaction instrumentation comes on by default and requires no
      // extra config for the basic case.
    }),
  ],
});

// Re-export for callers that want to emit custom spans:
//   import { tracer } from './telemetry';
//   tracer.startActiveSpan('my-op', span => { ...; span.end(); });
export const tracer = trace.getTracer(serviceName);
export { context };
