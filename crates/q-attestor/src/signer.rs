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

pub trait SigningBackend {
    fn operator_id(&self) -> u32;
    fn public_key(&self) -> PublicKey;
    fn sign(&self, preimage: &[u8], context: &[u8]) -> Signature;
}

pub struct EnclaveSigner<B: SigningBackend> {
    backend: B,
}

impl<B: SigningBackend> EnclaveSigner<B> {
    pub fn new(backend: B) -> EnclaveSigner<B> {
        EnclaveSigner { backend }
    }
}

impl<B: SigningBackend> AttestationSigner for EnclaveSigner<B> {
    fn operator_id(&self) -> u32 {
        self.backend.operator_id()
    }

    fn public_key(&self) -> PublicKey {
        self.backend.public_key()
    }

    fn sign(&self, message: &[u8], context: &[u8]) -> Signature {
        self.backend.sign(message, context)
    }
}

pub struct SoftBackend {
    operator_id: u32,
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl SoftBackend {
    pub fn from_seed(operator_id: u32, seed: &[u8; SEED_BYTES]) -> SoftBackend {
        let (public_key, secret_key) = ml_dsa::keygen(seed);
        SoftBackend {
            operator_id,
            public_key,
            secret_key,
        }
    }
}

impl SigningBackend for SoftBackend {
    fn operator_id(&self) -> u32 {
        self.operator_id
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn sign(&self, preimage: &[u8], context: &[u8]) -> Signature {
        let rnd = [0u8; 32];
        ml_dsa::sign(&self.secret_key, preimage, context, &rnd)
            .expect("ml-dsa sign over an in-bounds context")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const CTX: &[u8] = b"QUANTOVA/Q-ORACLE/ATTEST/v1";

    struct RemoteCustodian {
        inner: SoftBackend,
        calls: Cell<u32>,
    }

    impl SigningBackend for RemoteCustodian {
        fn operator_id(&self) -> u32 {
            self.inner.operator_id()
        }

        fn public_key(&self) -> PublicKey {
            self.inner.public_key()
        }

        fn sign(&self, preimage: &[u8], context: &[u8]) -> Signature {
            self.calls.set(self.calls.get() + 1);
            self.inner.sign(preimage, context)
        }
    }

    #[test]
    fn enclave_signature_verifies_against_the_backend_key() {
        let backend = SoftBackend::from_seed(3, &[0x51u8; 32]);
        let pk = backend.public_key();
        let signer = EnclaveSigner::new(backend);

        let message = b"observed fact";
        let sig = signer.sign(message, CTX);
        assert_eq!(signer.operator_id(), 3);
        assert!(ml_dsa::verify(&pk, message, &sig, CTX));
    }

    #[test]
    fn every_signature_leaves_through_the_backend_seam() {
        let custodian = RemoteCustodian {
            inner: SoftBackend::from_seed(4, &[0x52u8; 32]),
            calls: Cell::new(0),
        };
        let pk = custodian.public_key();
        let signer = EnclaveSigner::new(custodian);

        let sig = signer.sign(b"observed fact", CTX);
        assert!(ml_dsa::verify(&pk, b"observed fact", &sig, CTX));
        assert_eq!(signer.backend.calls.get(), 1);
    }
}
