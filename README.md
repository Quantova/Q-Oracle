# Q-Oracle

The Airlock. Q-Oracle is the one boundary in the Quantova stack where a foreign chain is verified, and it is the single repository exempt from the classical crypto deny list.

Quantova is a sovereign post quantum Layer 1 with only NIST standardized schemes and no classical escape hatch anywhere. That rule is absolute inside the chain. A bridge, though, has to read chains that still sign with elliptic curve cryptography, and reading them means checking their classical signatures. Q-Oracle is where that check is allowed to happen, off chain, behind a hard wall, so the classical dependency never touches the chain itself.

## What it is for

Q-Oracle is the off chain translation layer for the Quantova gateway. Its nodes watch a foreign chain, run that chain's own verification off chain, and turn a confirmed foreign event into a post quantum attestation the Quantova chain can accept. The attestation is a module lattice signature over the observed fact, carried with a proof of correct verification. The chain never sees the foreign signature. It sees only the post quantum attestation Q-Oracle produced.

This is the Airlock boundary named in POLICY-crypto section 7. Classical cryptography is permitted here and nowhere else, and nothing in the organization may import this repository. The isolation is enforced two ways. The repository is dropped from the classical crypto deny gate that every other repository runs, and no other crate is allowed to depend on it, so the classical code has exactly one home and no path inward.

## The one exemption, stated plainly

Every other Quantova repository runs `cargo deny` against the shared deny list, which makes classical crypto crates unrepresentable anywhere in the dependency tree. Q-Oracle's own deny file lifts that ban for this repository alone. License and advisory checks still apply here. The exemption is the whole point of the repository, and it is the reason nothing may import it.

## Status

This repository is early and holds no bridge code yet. The classical verification code arrives in the gateway phase, Wave F. Until then the repository fixes the boundary in place, the exemption, the no import rule, and the license, so the one place classical cryptography is ever allowed is decided before any of it is written.

## Governance and license

Governed by the crypto policy, POLICY-crypto, in the Quantova-Specs repository, with section 7 defining this Airlock boundary. Commits are authored by the owner only. Dual licensed under Apache 2.0 and MIT.
