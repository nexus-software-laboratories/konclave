use std::collections::BTreeMap;

use anyhow::anyhow;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::{Span, field, info_span};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer as _, Registry};

use crate::local_failure_log::{LOCAL_FAILURE_TARGET, LocalFailureLog, LocalFailureLogGuard};

const MAX_METADATA_FIELDS: usize = 32;
const MAX_METADATA_VALUE_CHARS: usize = 256;

pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
    _local_failure_log: Option<LocalFailureLogGuard>,
}

pub fn init() -> anyhow::Result<TelemetryGuard> {
    init_with_failure_log(None)
}

#[cfg(feature = "rust-service-mcp")]
pub(crate) async fn init_shared(installation_path: &std::path::Path) -> anyhow::Result<TelemetryGuard> {
    let path = installation_path.with_file_name("konclave-local-diagnostics.log");
    let log = match tokio::task::spawn_blocking(move || LocalFailureLog::open(&path)).await {
        Ok(Ok(log)) => Some(log),
        // Telemetry failure must remain explicit without denying otherwise valid clients.
        Ok(Err(_)) | Err(_) => {
            eprintln!("konclave: local failure diagnostic log is unavailable");
            None
        }
    };
    init_with_failure_log(log)
}

fn local_failure_layer<S>(writer: LocalFailureLog) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_writer(writer)
        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.target() == LOCAL_FAILURE_TARGET
        }))
}

fn init_with_failure_log(
    log: Option<(LocalFailureLog, LocalFailureLogGuard)>,
) -> anyhow::Result<TelemetryGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let format = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_writer(std::io::stderr)
        .with_filter(filter.clone());
    let registry = Registry::default();
    let (writer, log_guard) = match log {
        Some((writer, guard)) => (Some(writer), Some(guard)),
        None => (None, None),
    };
    let registry = registry.with(writer.map(local_failure_layer));

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
        registry
            .with(format)
            .with(tracing_opentelemetry::layer().with_tracer(tracer).with_filter(filter))
            .try_init()
            .map_err(|error| anyhow!("initializing OpenTelemetry subscriber: {error}"))?;
        return Ok(TelemetryGuard {
            provider: Some(provider),
            _local_failure_log: log_guard,
        });
    }

    registry
        .with(format)
        .try_init()
        .map_err(|error| anyhow!("initializing tracing subscriber: {error}"))?;
    Ok(TelemetryGuard {
        provider: None,
        _local_failure_log: log_guard,
    })
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
    fn local_failure_log_excludes_other_targets_and_ambient_span_fields() {
        use std::io::Read as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        KonclaveSecretStorage::ensure_owner_protected_directory(&directory).unwrap();
        let path = directory.join("diagnostics.log");
        let (writer, guard) = crate::local_failure_log::LocalFailureLog::open(&path).unwrap();
        let subscriber = tracing_subscriber::Registry::default()
            .with(super::local_failure_layer(writer));
        tracing::subscriber::with_default(subscriber, || {
            let _span = tracing::info_span!(
                target: crate::local_failure_log::LOCAL_FAILURE_TARGET,
                "private_parent",
                profile = "PRIVATE-PROFILE",
                body = "PRIVATE-CREDENTIAL"
            )
            .entered();
            tracing::warn!(
                target: crate::local_failure_log::LOCAL_FAILURE_TARGET,
                stage = "profile_attach",
                code = "profile_locked",
                connection = "0123456789abcdef",
                request_sequence = 0_u64
            );
            tracing::warn!(target: "unrelated", body = "PRIVATE-PAYLOAD");
        });
        drop(guard);
        let mut output = String::new();
        KonclaveSecretStorage::open_owner_protected_file(&path)
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        assert!(output.contains("profile_locked"));
        assert!(!output.contains("PRIVATE"));
        assert!(!output.contains("private_parent"));
        assert_eq!(output.lines().count(), 1);
    }

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
