# Q-Oracle

The Airlock. Q-Oracle is the one boundary in the Quantova stack where a foreign chain is verified, and it is the single repository exempt from the classical crypto deny list.

Quantova is a sovereign post quantum Layer 1 with only NIST standardized schemes and no classical escape hatch anywhere. That rule is absolute inside the chain. A bridge, though, has to read chains that still sign with elliptic curve cryptography, and reading them means checking their classical signatures. Q-Oracle is where that check is allowed to happen, off chain, behind a hard wall, so the classical dependency never touches the chain itself.

## What it is for

Q-Oracle is the off chain translation layer for the Quantova gateway. Its nodes watch a foreign chain, run that chain's own verification off chain, and turn a confirmed foreign event into a post quantum attestation the Quantova chain can accept. The attestation is a module lattice signature over the observed fact. The chain never sees the foreign signature. It sees only the post quantum attestation Q-Oracle produced.

## What is in the repository

This repository holds the working bridge oracle, not a placeholder. It carries the airlock isolation boundary, both admission paths, and the light client verifiers for the trustless chains.

The federated admission path takes an operator quorum. Each operator watches its own independent source, signs the observed fact with a module lattice key, and the gateway admits the deposit only when a supermajority of distinct operators agree and the per asset and per epoch budgets still hold.

The trustless admission path takes a proof in place of a quorum. A proof backed corridor is verified from the foreign chain's own consensus, and the proven amount, recipient, and reference are carried forward, never the caller's word.

The trustless corridors are Bitcoin, Ethereum, and Cosmos. The Bitcoin verifier follows the proof of work header chain, holds it to a pinned checkpoint and a cumulative work floor, and confirms the deposit to the network confirmation depth. The Ethereum verifier runs a sync committee light client with a BLS aggregate check and reads the deposit from the receipt under a finalized header. The Cosmos verifier runs a Tendermint light client with a validator overlap rule and reads the deposit value at its proven key under the committed app hash.

A proof backed deposit is admitted here but not minted here. The authoritative on chain mint stays behind the trustless deposit seam, so this repository never opens a mint entry point of its own.

## Running it

The oracle keeps its sense of time from the Quantova chain head it reads at the address in `Q_ORACLE_CHAIN_RPC`. When the anchor file pins a Quantova committee, the oracle takes a head only with the finality certificate for that exact block, verified against the pinned committee, and refuses any head that lacks one. The node must then serve the block header and its certificate beside the head. Without a pinned committee the head is not signed, so it must come from a node the operator runs, over loopback or a private link that no one else can reach or sit in the middle of. In both cases the oracle refuses a head that moves backwards and caps how far one answer can move it. The bridge epoch beside the head is never signed and only ever steps forward by one after a fixed wait. On a first boot with no saved height the oracle takes no head on trust, so the operator sets `Q_ORACLE_EXPECTED_HEAD` to the current chain height and `Q_ORACLE_EXPECTED_EPOCH` to the current bridge epoch, and the first answer is capped at those values.

The proof backed corridors read their trust anchors from the file named by `Q_ORACLE_ANCHORS_FILE`. The file must be a regular file readable by its owner alone, or the oracle refuses to start. It is a JSON object with an optional section for each of bitcoin, ethereum, cosmos and quantova. Each anchor must also appear in the list pinned in the code, the Bitcoin checkpoint in `PINNED_CHECKPOINTS`, the Ethereum weak subjectivity block root in `PINNED_BLOCK_ROOTS`, and the Cosmos trusted header and validator set in `PINNED_TRUSTED_STATES`. The pinned lists ship empty, so every proof backed corridor refuses deposits until the real anchors are added at mainnet. A corridor with no anchor refuses every deposit.

The Ethereum light client follows the sync committee through `rotate_ethereum_committee`. Anyone may relay a light client update that carries the next sync committee. The oracle accepts it only when a supermajority of the current committee signed it and the next committee and the finalized header are proven against the signed state. The period advances once a finalized header crosses into the next period. The execution block number a deposit reports is proven against the beacon block body, never taken on the caller's word.

Proof verification runs outside the shared state lock on a copy of the anchor, after the cheap structural, replay and budget checks, and at most four proofs are verified at once. Each address may submit two proofs a second.

The Cosmos verifier checks Ed25519 more strictly than the ZIP 215 rules CometBFT uses. It refuses small order keys and commitments and non canonical encodings, and it uses the cofactorless check. A signature the Cosmos chain accepts under the looser rules can be ignored here, so a commit can fall short of two thirds and the light client stops until a later commit clears it. It never accepts a signature the chain would refuse.

## The one exemption, stated plainly

Every other Quantova repository runs cargo deny against the shared deny list, which makes classical crypto crates unrepresentable anywhere in the dependency tree. Q-Oracle's own deny file lifts that ban for this repository alone. License and advisory checks still apply here. The exemption is the whole point of the repository, and it is the reason nothing may import it. The isolation is enforced two ways. The repository is dropped from the classical crypto deny gate that every other repository runs, and no other crate is allowed to depend on it, so the classical code has exactly one home and no path inward.

## Governance and license

Governed by the crypto policy, POLICY-crypto, in the Quantova-Specs repository, with section 7 defining this Airlock boundary. Commits are authored by the owner only. Dual licensed under Apache 2.0 and MIT.
