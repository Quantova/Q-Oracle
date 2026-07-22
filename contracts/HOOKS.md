# Chain side hook (STUB, flagged, not built here)

This file is a specification stub. It marks the one place where the bridge needs a chain side facility that the gateway contract cannot express on its own. Nothing in this wave modifies Quantova-Chain core or the pinned QVM. The gateway contract in this repository holds the registered operator set, the quorum verification, the replay record, the caps, the finality gate, and the pause authority, all at the execution layer. The item below is the remaining hook and it is a founder decision that belongs to the chain and staking stream, not to this build.

## The bonded bridge attester role

The gateway reads its operator set from its own authenticated contract state and rotates it by operator quorum. That is membership. It is not bonding. Bonding a native stake to an operator and slashing that stake on proven misbehaviour is a staking layer power that a contract cannot reach, because a contract cannot burn native validator stake and cannot read the equivocation record that consensus keeps.

The hook has three parts.

First a bonded bridge attester role in the economics and staking layer. An operator posts native QTOV to a bridge attester bond that is separate from validator stake and separate from the validator set. The bond is a wide margin above the value the operator can move, and an operator with no active bond cannot be a member of the gateway operator set.

Second a slashing binding. A proof of operator equivocation, meaning two conflicting signed facts over the same source reference, or a proof of a signature over a fact that the source chain finality never carried, slashes the bond in full and removes the operator from the set. The divergence and dedup logic in the off chain operator service and the replay record in the gateway produce the evidence. The slash itself is a staking layer action.

Third a safety pause lane. The pause and the reorg pause entries in the gateway must reach the chain even when the mempool is congested, so the chain needs a reserved priority lane for a bridge safety transaction. Without it a griefing flood could delay a pause while a bad corridor drains.

## Status and flag

This is a stub. It is not implemented in this wave and it must not be improvised into chain core here. It is flagged for the founder and the chain and staking stream. The bridge is safe to run on testnet without the bond by seeding the operator set at genesis and rotating by quorum, but the trust minimized claim rests on the bond, so the mainnet path needs this hook decided and built by the owning stream first.
