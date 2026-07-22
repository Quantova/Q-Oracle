use qtv_crypto::ml_dsa::{self, PublicKey, SecretKey, Signature, SEED_BYTES};

pub trait AttestationSigner {
    fn operator_id(&self) -> u32;
    fn public_key(&self) -> PublicKey;
    fn sign(&self, message: &[u8], context: &[u8]) -> Signature;
}

pub struct SoftSigner {
    operator_id: u32,
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl SoftSigner {
    pub fn from_seed(operator_id: u32, seed: &[u8; SEED_BYTES]) -> SoftSigner {
        let (public_key, secret_key) = ml_dsa::keygen(seed);
        SoftSigner {
            operator_id,
            public_key,
            secret_key,
        }
    }
}

impl AttestationSigner for SoftSigner {
    fn operator_id(&self) -> u32 {
        self.operator_id
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn sign(&self, message: &[u8], context: &[u8]) -> Signature {
        let rnd = [0u8; 32];
        ml_dsa::sign(&self.secret_key, message, context, &rnd)
            .expect("ml-dsa sign over an in-bounds context")
    }
}
