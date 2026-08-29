# Packaged clean-install acceptance

The required `Packaged clean-install acceptance` job operates on downloaded workflow
artifacts, not Cargo build outputs. It extracts two independent client installations,
the standalone relay, and the Docker-loadable relay candidate into job-private paths.

## Automated evidence

The job proves:

- `relay-bootstrap` creates a verifier-only access document and protected,
  endpoint-bound enrollment source without printing or passing the raw credential;
- one `init` command configures all later session profiles without per-session relay
  variables;
- `doctor` recognizes the extracted daemon and plugin and reaches the relay through a
  locally generated certificate chain trusted by the client process;
- one packaged shared-service process hosts independently enrolled profiles and the
  thin plugin contains no daemon;
- two shared-service clients pair through one capability and exchange exact messages
  in both directions;
- both clients exchange and independently activate one exact collaboration-policy
  digest, retain it across service restart, and prove ordinary text cannot authorize
  an autonomous reply through separate interactive and delivery connections;
- an untrusted relay certificate is rejected before the same endpoint succeeds with
  its temporary CA explicitly trusted;
- disconnecting one client, sending while it is offline, and reconnecting replays the
  exact missed message;
- restarting the one service through a second, byte-identical extraction preserves
  profile identity;
- an active pairing can be cancelled without exposing Invitation, JoinProof, Welcome,
  cursor, route, or peer-binding fields;
- native and Docker-loaded relays expose the same enrollment, pairing, delivery, and
  recovery behavior;
- relay databases and logs contain neither message plaintext, pairing capabilities,
  nor the protected enrollment record;
- service process arguments and environments contain no relay credential or
  endpoint variables and no tested secret/plaintext sentinels;
- removing extracted installations leaves profile databases intact; and
- Docker cleanup removes the exact acceptance container and loaded image while
  preserving the pre-run engine baseline.

The test compiles only its CI harness. Every process under test—the CLI, shared service
and its replacement extraction, standalone relay, and container image—comes from the
packaged release candidates.

Because this is the first packaged prerelease, no earlier release exists for a
cross-version schema migration. The job covers replacement-install mechanics by
restarting a durable profile through a second clean extraction. It covers the
documented archive uninstall path by removing both installation roots while
confirming the separate profile state remains.

## Proprietary Copilot boundary

CI simulates the Copilot host contract around the packaged thin client: registered
SDK tools, authenticated profile attachment, delivery settlement, idle injection
safety, terminal updates that do not enter model turns, and no process launch.
Existing plugin tests exercise session callbacks, slash commands, reconnect, and
safety framing.

The packaged shared-service scenario now verifies the daemon-owned collaboration
boundary without cloud inference. Each logical client opens fresh interactive and
delivery handshakes under one authenticated session key and claims the live delivery
lease. After service restart, ordinary text cannot authorize an autonomous turn; an
explicit reply preserves its exact reply chain and remains terminal at the peer. Rust
service tests cover exact directed-request claim, one-use response authorization,
no-response completion, claim renewal, capability negotiation, and crash recovery.
Packaged plugin tests cover exact request authorization, one correlated send, idle
completion, and acknowledgment after the terminal handling outcome.

The CI-safe `shared_service_process` test additionally attaches 20 logical clients
with 40 authenticated interactive/delivery lanes and 20 delivery leases to one PID,
proves distinct identities and profile stores, checks process/descriptor/memory
bounds, pairs two profiles, exchanges an offline message and exact reply, restarts the
service, and verifies relay opacity.

The test does not perform browser OAuth against the proprietary Copilot CLI service
and does not request cloud model inference. Those operations require a billed,
interactive external account and produce nondeterministic model output. Konclave's
public protocol, package, local process, and delivery claims do not depend on that
external behavior.
