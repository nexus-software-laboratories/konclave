use std::collections::BTreeMap;

use anyhow::anyhow;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::{Span, field, info_span};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

const MAX_METADATA_FIELDS: usize = 32;
const MAX_METADATA_VALUE_CHARS: usize = 256;

pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

pub fn init() -> anyhow::Result<TelemetryGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let format = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_writer(std::io::stderr);

    if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        use opentelemetry_otlp::WithExportConfig;

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                Resource::builder()
                    .with_service_name(env!("CARGO_PKG_NAME"))
                    .build(),
            )
            .build();
        let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
        global::set_tracer_provider(provider.clone());
        Registry::default()
            .with(filter)
            .with(format)
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .map_err(|error| anyhow!("initializing OpenTelemetry subscriber: {error}"))?;
        return Ok(TelemetryGuard {
            provider: Some(provider),
        });
    }

    Registry::default()
        .with(filter)
        .with(format)
        .try_init()
        .map_err(|error| anyhow!("initializing tracing subscriber: {error}"))?;
    Ok(TelemetryGuard { provider: None })
}

#[must_use]
pub fn metadata_only_span(operation: &'static str, metadata: &BTreeMap<String, String>) -> Span {
    let safe_metadata = sanitize_metadata(metadata);
    info_span!(
        "service.operation",
        operation,
        metadata_count = safe_metadata.len(),
        body = field::Empty,
        authorization = field::Empty
    )
}

#[must_use]
pub fn sanitize_metadata(metadata: &BTreeMap<String, String>) -> Vec<KeyValue> {
    metadata
        .iter()
        .filter(|(key, _)| !is_sensitive_field(key))
        .take(MAX_METADATA_FIELDS)
        .map(|(key, value)| {
            KeyValue::new(
                key.clone(),
                value
                    .chars()
                    .take(MAX_METADATA_VALUE_CHARS)
                    .collect::<String>(),
            )
        })
        .collect()
}

#[must_use]
pub fn is_sensitive_field(field_name: &str) -> bool {
    let normalized = field_name.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "password",
        "secret",
        "token",
        "body",
        "content",
    ]
    .iter()
    .any(|sensitive| normalized.contains(sensitive))
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        MAX_METADATA_FIELDS, MAX_METADATA_VALUE_CHARS, is_sensitive_field, metadata_only_span,
        sanitize_metadata,
    };

    #[test]
    fn sensitive_fields_are_excluded_and_values_are_bounded() {
        let mut metadata = BTreeMap::from([
            ("request_id".to_string(), "a".repeat(512)),
            ("api_token".to_string(), "secret".to_string()),
            ("body".to_string(), "content".to_string()),
        ]);
        for index in 0..40 {
            metadata.insert(format!("safe_{index}"), "value".to_string());
        }

        let sanitized = sanitize_metadata(&metadata);
        assert_eq!(sanitized.len(), MAX_METADATA_FIELDS);
        assert!(sanitized.iter().all(|entry| {
            !is_sensitive_field(entry.key.as_str())
                && entry.value.to_string().len() <= MAX_METADATA_VALUE_CHARS
        }));
    }

    #[test]
    fn metadata_only_span_reserves_sensitive_fields() {
        let metadata = BTreeMap::from([
            ("request_id".to_string(), "abc".to_string()),
            ("body".to_string(), "secret".to_string()),
        ]);
        let span =
            tracing::subscriber::with_default(tracing_subscriber::Registry::default(), || {
                metadata_only_span("demo", &metadata)
            });
        assert_eq!(
            span.metadata().map(tracing::Metadata::name),
            Some("service.operation")
        );
    }
}
