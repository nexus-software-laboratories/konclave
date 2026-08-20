# Protocol v1 binary fixtures

These deterministic, synthetic Protocol Buffers messages are the compatibility
baseline for `konclave.protocol.v1`. Rust and TypeScript readers must decode each
fixture and re-encode the same bytes. The values are test data, not credentials,
production identifiers, or cryptographic test vectors.

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `acknowledge-request.bin` | 38 | `4a916b322d0af333cc657e200f2daa669af79887b8a8502efd1af87b83d2cf9f` |
| `application-message.bin` | 62 | `9d1bf4649b3f47bba9124a91f3f22e879da3a928651b2558f9c2c09cbfdf8cdf` |
| `conversation-state.bin` | 164 | `3c78dc0c93743ee53dcaa8737b7ed4e8c69004d831b4287a0faafdf44884bb58` |
| `device-credential-binding.bin` | 212 | `8d9d93e470d0adccdc0298312304b9669e1102769bf69ecadac3453d75651ab3` |
| `invitation.bin` | 240 | `cdca99b5057721c7f557b3fe2d04a5cd5ffb0e8b022790e592371612d9b65183` |
| `join-proof.bin` | 492 | `edd36bc487fae333ab4acd701a999355e3897e9b7979ce79a08e0cc343a19539` |
| `membership-change.bin` | 156 | `9f0025ac415b67df907e6f529554770bf3e14121fa435f68219097ad4be598db` |
| `membership-commit-bundle.bin` | 84 | `409e5a3b8b234ba6b89b3f26864942ecb7c0a55256384824da8076fdd5001091` |
| `membership-control.bin` | 654 | `3ae4f1b305a171f1ee4777064024cb277fd07abe84d88a809f916133e6622220` |
| `relay-envelope.bin` | 102 | `561b793b22ce2d1ce8cda1b7066b1f7499b5ef6ed599915e3763c1bf4b84ec82` |
| `replay-page.bin` | 218 | `643ff81ba25e4322e38825c0ccfe91d12c0884a8115b227222ed3eb64db5c01d` |
| `replay-request.bin` | 38 | `2667f31090b525e67584cc7f876893b93df85ee10d8057f395091697f51af69e` |
| `route-bound-invitation.bin` | 276 | `90056ccfe65c943ba009163085acec38fb7b9a26bdf71abcfbd56b9c74494600` |
| `stored-relay-envelope.bin` | 106 | `259830618f14a86b64095792b32c781d5c0e419999fd8a3ff4935783841101c5` |

Before the first stable v1 release, maintainers can regenerate the complete set with
`cargo run -p KonclaveProtocolContracts --example generate_v1_fixtures`. After release,
existing fixtures are immutable; compatible additions receive new fixtures and
breaking contracts require a new major-version directory.
