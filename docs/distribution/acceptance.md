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
- two simulated Copilot host sessions launch the daemon bundled in the cached plugin,
  enroll independent relay principals, and pair through one capability;
- messages arrive automatically through the authenticated adapter channel in both
  directions without a receiver sync prompt;
- an untrusted relay certificate is rejected before the same endpoint succeeds with
  its temporary CA explicitly trusted;
- killing a daemon before adapter acknowledgment redelivers the same stable
  notification after restart through a second, byte-identical extraction;
- an active pairing can be cancelled without exposing Invitation, JoinProof, Welcome,
  cursor, route, or peer-binding fields;
- native and Docker-loaded relays expose the same enrollment, pairing, delivery, and
  recovery behavior;
- relay databases and logs contain neither message plaintext, pairing capabilities,
  nor the protected enrollment record;
- daemon process arguments and environments contain no legacy relay credential or
  endpoint variables and no tested secret/plaintext sentinels;
- removing extracted installations leaves profile databases intact; and
- Docker cleanup removes the exact acceptance container and loaded image while
  preserving the pre-run engine baseline.

The test compiles only its CI harness. Every process under test—the CLI, both daemon
instances, plugin-bundled replacement daemon, standalone relay, and container
image—comes from the packaged release candidates.

Because this is the first packaged prerelease, no earlier release exists for a
cross-version schema migration. The job covers replacement-install mechanics by
restarting a durable profile through a second clean extraction. It covers the
documented archive uninstall path by removing both installation roots while
confirming the separate profile state remains.

## Proprietary Copilot boundary

CI simulates the Copilot host session contract around the packaged plugin: session
identity, MCP child launch, outbound authenticated adapter attachment, idle delivery,
prompt framing, and acknowledgment. Existing plugin tests exercise the packaged
extension's session callbacks and safety framing.

The test does not perform browser OAuth against the proprietary Copilot CLI service
and does not request cloud model inference. Those operations require a billed,
interactive external account and produce nondeterministic model output. Konclave's
public protocol, package, local process, and delivery claims do not depend on that
external behavior.
