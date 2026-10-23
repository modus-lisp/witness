# witness

A web of trust for facts about remote machines and their keys, on Nostr.

When you are about to encrypt to an enclave, you need to know two things. First, whether the key really belongs to a machine running code you trust. Second, who says so. witness answers both from signed statements published by people and machines, weighted by a web of trust you already have: whom you follow.

```lisp
(witness:make-policy statements
                     :roots (list my-npub)
                     :follows contact-lists        ; NIP-02 kind 3 events
                     :max-depth 2)
```

## Statements

Statements are [DEP-14](https://github.com/bitcoin-deposits/deposits/blob/main/DEP-14.md) attestation events: kind 55502, a JSON body with a `method`, signed by whoever stands behind it. DEP-14 defines identity checks of a pubkey (`nip05`, `challenge`, `proclaim`, `ringsig`); witness reads those and adds facts about things that are not pubkeys.

| method | claim |
|---|---|
| `attested` | the signer fetched this vendor-signed attestation document from this endpoint, and embeds the document |
| `reproduced` | the signer built `repo` at `commit` with this toolchain and got this measurement |
| `observed` | the signer saw a value with no vendor signature (its word only) |
| `endorsed` | the signer accepts a release for use |
| `routed` | the signer read a service image's source and says which providers each model's requests can go to |
| `proclaim` | the signer vouches for the key `npub`, optionally bounding how far it may vouch in turn (`depth`) |
| `revoked` | the signer withdraws one of its own statements, named by id |

How subjects are tagged, so relays can index them:
- A pubkey subject goes in `p`.
- Anything else goes in `i`: `endpoint:HOST`, `source:REPO@COMMIT[:TARGET]`, `measurement:PCR0|PCR1|PCR2`.

`contrib/opensecret-routed.lisp` reads Maple's OpenSecret route table at the source an approval names and signs it as a `routed` statement. It refuses anything it can't parse, and publishes nothing.

## Trust

Trust starts at your roots and spreads along two kinds of edges:

- **Follows.** A trusted key's NIP-02 contact list. This is the web of trust Nostr already runs on: relays, agents and clients that admit "whoever I follow".
- **Proclamations.** A trusted key vouching for one specific key.

Each edge costs a hop, up to `max-depth`.

A statement counts when all of these hold:
- its signature verifies;
- its signer is trusted;
- its signer has not revoked it;
- for `attested`, the embedded document verifies against the vendor's root and actually says what the statement claims.

Agreement is counted by distinct trusted signers, never by number of statements. Reproducers who disagree about a measurement are reported as a conflict.

## No clock

Nostr timestamps are whatever the signer wrote, so nothing here trusts them:
- **No expiry.** Statements don't expire.
- **No time ordering.** Nothing is ordered by `created_at`.
- **Revocation by id.** A revocation names the event it voids, is final, and cannot itself be revoked. A key holder therefore cannot resurrect a revoked statement by back-dating or forward-dating a new one.
- **Bitcoin anchoring.** Where a bound in time matters, a statement can carry `["block", HEIGHT, HASH]` ("not before") for a caller that checks it against its own view of the chain.

## Evidence

`witness/evidence` checks the documents `attested` statements embed. For AWS Nitro, it uses [cl-sev-snp](https://github.com/modus-lisp/cl-sev-snp): the certificate chain to AWS's root, the signature, and the measurement, key and nonce the statement claims. A Nitro document is judged at its own AWS-signed timestamp: the one clock here, and it is AWS's, inside AWS-rooted evidence.

## Keys

A machine signs with its own key (`load-or-create-key`, a 0600 file). Your own root key stays in your own client and signs only `proclaim` statements. Secrets are held by cl-nostr in natrium's fixed (non-moving) memory.

## Use

```lisp
(asdf:load-system :witness/evidence)
(asdf:test-system :witness)        ; offline; includes a real Nitro document
```

Depends on cl-nostr, natrium, secp256k1-fast, json-simple and cl-sev-snp.

## License

MIT
