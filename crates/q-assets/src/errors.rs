#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetError {
    AssetNotRegistered,
    ZeroAmount,
    MintCapExceeded { minted: u128, cap: u128, add: u128 },
    UnlockCapExceeded { amount: u128, cap: u128 },
    EpochCapExceeded { minted: u128, cap: u128, add: u128 },
    InsufficientMinted { minted: u128, amount: u128 },
    EscrowInvariantBroken { escrowed: u128, minted_after: u128 },
}
