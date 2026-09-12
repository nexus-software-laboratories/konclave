FROM rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7 AS build
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p KonclaveA2AGatewayHost --bin KonclaveA2AGateway

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
RUN groupadd --system --gid 10001 appgroup \
    && useradd --system --uid 10001 --gid appgroup --create-home appuser \
    && install -d -m 0700 -o appuser -g appgroup \
        /var/lib/konclave/a2a/tasks \
        /var/lib/konclave/a2a/objects
WORKDIR /app
COPY --from=build /workspace/target/release/KonclaveA2AGateway /app/KonclaveA2AGateway
COPY apps/Konclave.A2AGateway/gateway-config.container.json \
    /usr/share/konclave/a2a/gateway-config.json
ENV KONCLAVE_A2A_GATEWAY_CONFIG_FILE=/etc/konclave/a2a/gateway-config.json \
    SERVICE_HEALTH_ADDRESS=127.0.0.1:8090
USER appuser
EXPOSE 8090
VOLUME ["/var/lib/konclave/a2a/tasks", "/var/lib/konclave/a2a/objects"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/app/KonclaveA2AGateway", "--healthcheck"]
ENTRYPOINT ["/app/KonclaveA2AGateway"]
