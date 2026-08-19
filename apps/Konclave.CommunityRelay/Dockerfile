FROM rust:1.89-bookworm AS build
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p KonclaveCommunityRelay

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home appuser
RUN install -d -o appuser -g appuser /var/lib/konclave
WORKDIR /app
COPY --from=build /workspace/target/release/KonclaveCommunityRelay /app/KonclaveCommunityRelay
ENV SERVICE_HTTP_ADDRESS=0.0.0.0:8080 \
    SERVICE_HEALTH_ADDRESS=127.0.0.1:8080 \
    KONCLAVE_RELAY_ACCESS_FILE=/run/secrets/konclave-relay-access.json \
    KONCLAVE_RELAY_DATABASE_PATH=/var/lib/konclave/relay.sqlite
USER appuser
EXPOSE 8080
VOLUME ["/var/lib/konclave"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/app/KonclaveCommunityRelay", "--healthcheck"]
ENTRYPOINT ["/app/KonclaveCommunityRelay"]
