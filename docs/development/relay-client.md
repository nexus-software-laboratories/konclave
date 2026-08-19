# Outbound relay client

`Konclave.ClientLibrary` owns the portable outbound HTTP and WebSocket adapter used by
trusted endpoint processes. It depends only on public domain and protocol contracts;
it does not assume one relay deployment or expose bearer bytes to command, extension,
or model-facing APIs.

## Endpoint policy

`RelayEndpoint` accepts HTTPS endpoints and permits plaintext HTTP only for
`localhost` or a loopback IP address. It rejects embedded user information, query
parameters, fragments, and unsupported schemes. An explicit base path is preserved
for reverse-proxy deployments.

HTTP redirects and automatic system/environment proxy discovery are disabled. This
prevents an authenticated request from forwarding its bearer header to a different
location or moving a loopback plaintext request through an external proxy. TLS
validation uses platform trust roots.

Transport TLS uses rustls with the ring provider. MLS remains on the exact-pinned
AWS-LC provider selected by ADR 0001; keeping those provider selections independent
allows the current WebPKI release without changing the MLS cryptographic profile.

## Credential custody

`RelayAccessCredential` owns exactly 32 bytes and zeroizes them on drop. It has no
`Debug` or `Clone` implementation. Cloneable relay clients share one credential
through an `Arc` rather than copying bearer bytes.

The credential creates a short-lived authorization header for each request. Temporary
base64 and header-construction buffers are zeroized. HTTP and WebSocket errors discard
library error text and URLs, exposing only stable bounded client or relay codes.

Tungstenite can format complete handshakes and frames at `log` trace level. The
workspace compiles dependency trace logging out with `log`'s static maximum-level
feature, preventing bearer headers and opaque payloads from entering those log calls.
Enabling a conflicting static trace feature fails compilation rather than silently
weakening this boundary. CI also requires exactly one `log` 0.4 package instance at
the selected version, preventing Tungstenite from resolving to an uncapped duplicate
facade inside shipped workspace binaries.

The caller must clear any source byte or string copy used to construct the credential.
The local daemon will load that source from sealed profile storage.

## HTTP operations

`RelayTransport` provides typed submit, replay, and acknowledgment methods:

- request DTOs are encoded from validated domain values;
- redirects are never followed;
- each operation has a connect and total deadline;
- successful responses require `application/protobuf`;
- `Content-Length` is checked when present;
- chunked responses are accumulated only up to the protocol-specific hard limit;
- non-success behavior reads the bounded `x-konclave-error-code` header, never
  human-readable response text.

## WebSocket watch

`connect_watch` opens one authenticated session and sends a bounded `ReplayRequest`.
The returned `RelayWatchSession` is caller-owned and spawns no detached task.

`next_page`:

- accepts only bounded binary `ReplayPage` messages;
- responds to Ping frames within the write deadline;
- uses a read deadline longer than the relay's heartbeat failure window;
- surfaces stable close reasons for permanent route or protocol rejection;
- treats transport closure, timeout, malformed pages, and unexpected frame kinds as
  explicit errors.

The caller processes and durably acknowledges pages. After any watch error, it creates
a new session from the last durable cursor using bounded backoff. This keeps reconnect
lifecycle and cancellation owned by the daemon rather than hidden inside the client.

## Validation

Focused tests prove:

- TLS-or-loopback endpoint validation and base-path preservation;
- exact canonical bearer parsing;
- no bearer forwarding across HTTP redirects;
- no automatic environment/system proxy use for credential-bearing requests;
- compile-time exclusion of dependency trace logs that can format handshakes or frames;
- bounded chunked response handling;
- idempotent submit, replay, and acknowledgment against the community relay;
- live watch delivery and reconnect replay;
- stable HTTP and WebSocket authorization failures.
