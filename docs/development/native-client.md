# Explicit native client composition

`KonclaveClientLibrary::native` exposes conversation processing over host-owned
journals and ordered relay composition over an explicit native host. It does not
open a local profile, call local-service RPC, discover keys, or grant membership
from an HTTP identity. [ADR 0031](../adr/adr-0031-embeddable-durable-native-client.md)
records the proposed extraction boundary.

## Dependencies and ownership

`NativeConversationProcessor` borrows a `NativeConversationJournal`, an explicitly
opened native `DeviceIdentity`, and an existing project-sealed MLS storage handle.
The handle accepts project sealed wrappers, not an arbitrary unsealed provider.
The public composition type does not require SQLite or a local-profile path.
This does not imply a SQLite-free dependency graph: the existing cryptographic
crate still enables the SQLite storage feature.

The embedding process is a trusted native endpoint for its own keys and plaintext.
It must hold one exclusive operation owner throughout processing and fence every
journal and MLS mutation against that owner. A process mutex alone does not fence
another service replica. Loss of custody, ownership or record authentication is an
error, never permission to select another identity or memory-only store.

The journal adapter owns backend-specific transactions, sealing, bounds and
freshness. Bind every observation to the exact endpoint, conversation, route,
envelope, message, sender, cursor and epoch. Do not persist the public opened
record types directly in ordinary tables or logs. Seal application content,
control, credentials and policy under the existing custody/context scheme.
AEAD and writer CAS do not detect coherent old checkpoints, selective restore
or deletion by an authorized storage/restore operator.

## Atomic admission and recovery

`reserve_application` is an atomic semantic operation, not a notification that
the host checked authority earlier. In the same commit, its adapter must:

- Revalidate current native authority and the exact operation scope.
- For a response, verify and consume the exact live handling claim once.
- Reserve immutable message/envelope identities and the next sender counter.
- Persist immutable terminal response intent sufficient for exact recovery.

Policy revocation, lease loss or a competing response that wins before that commit
must deny new admission. Message content and a caller-supplied policy flag are not
authority. Membership, roles, collaboration policy and host task claims remain
independent checks.

Already committed recovery is not new admission. Resume the exact original
identities, content, reply correlation, timestamp and ciphertext. Never replace
committed response intent with newer mutable source content. Outbound failure may
leave a permanent counter gap; it cannot roll the counter back into reuse.

The shared processor preserves the split-journal ordering from
[ADR 0004](../adr/adr-0004-daemon-profile-journal.md). Authenticated inbound plaintext
is saved before receiver-ratchet persistence, and only exact saved evidence can
justify completion after an already-processed generation. An arbitrary MLS failure
does not prove success. Membership journals retain authenticated control and the
complete expected next policy before applying the MLS transition.

## Relay/session composition

`NativeSession<H, T>` accepts an explicit `NativeSessionHost`, `RelayTransport` and
shared asynchronous submission gate. All producers for that endpoint must share
the gate, including host-specific policy and membership operations. Cloning the
session shares its dependencies and gate; constructing separate gates does not
establish independent writer ownership.

Host membership operations can retain an owned guard from that exact gate while
draining applications, selecting an existing immutable membership retry, and
submitting it. The `*_with_gate` methods reject a guard from another mutex before
host or relay effects. Membership acceptance returns the original encrypted
Welcome, not newly generated enrollment material.

The host implements bounded native operations using the shared processor and its
authenticated journal adapter. `send` distinguishes new admission from immutable
ready/accepted/terminal retries. A changed body or reply target cannot reuse the
stable message identity. Accepted retries retain the original timestamp and cursor.
New work drains older ready envelopes first. Exact ready retries recheck native
membership without turning previously committed response recovery into a new
collaboration-policy admission.

Replay checks contiguous cursors and exact route evidence before processing a
page. Acknowledgment follows durable completion; failure partway through a page
does not acknowledge the unfinished suffix. An effective acknowledgment can be
ahead of the requested cursor but cannot regress or change the route.

The session starts no tasks, watch loops or blocking workers. It owns the futures
it returns, while the host owns blocking execution and shutdown. A host that
starts workers must bound, retain and join them even if a calling future is
dropped. Stop new admission and drain admitted operations before releasing
persistence ownership. Do not interpret cancellation after a durable commit as
evidence that the operation never happened.

For blocking composition, retain both operation admission and submission ownership
in the worker itself. Keeping a guard only in the calling future releases it when
that future is cancelled, even though a blocking operation can still be running.
`send_with_gate` permits retaining an `Arc` of the exact owned guard across that
boundary without reacquiring or replacing the endpoint's submission mutex.

## Qualification and adapter evidence

The focused `Native client conformance` workflow runs on drafts. It directly
executes native processor tests, relay/session classifier and orchestration tests,
and daemon conversation/application/persistence tests, with format, Clippy and
conservative dependency relevance checks.

The bounded sealed in-memory processor fixture proves actual MLS composition and
checkpoint decisions, not process durability. The separate fake host/relay tests
prove orchestration and finite evidence categories, not cryptographic or database
correctness. A production adapter still needs direct atomicity, sealing, restart,
claim-race and stale-writer tests against its actual durable backend. Existing
daemon SQLite tests qualify the daemon adapter, not an unrelated service database.

For A2A consumers, keep `A2ATaskSubmitter` as the gateway seam. Native endpoint
composition is not a fake local-service JSON facade, and an ordinary A2A HTTP edge
still terminates plaintext as described by
[ADR 0018](../adr/adr-0018-fail-closed-protected-a2a-handoff.md).
