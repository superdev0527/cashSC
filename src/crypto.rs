pub trait PublicKey {
    fn serialize(&self) -> [u8; 33];
}

pub trait Signature {
    fn serialize_der(&self) -> Vec<u8>;
}

pub trait SecretKey {
    fn from_slice(slice: &[u8]) -> Result<Self, Box<std::error::Error>>;
}

pub trait Crypto {
    type SecretKey: SecretKey;
    type PublicKey: PublicKey;
    type Signature: Signature;

    fn hash160(data: &[u8]) -> [u8; 20];
    fn single_sha256(data: &[u8]) -> [u8; 32];
    fn double_sha256(data: &[u8]) -> [u8; 32];

    fn sign(&self,
            message: &[u8],
            key: &Self::SecretKey) -> Self::Signature;

    fn secret_to_pub_key(&self, key: &Self::SecretKey) -> Self::PublicKey;
}


pub mod secp256k1 {
    use super::{PublicKey, Signature, SecretKey, Crypto};

    use sha2::{Sha256, Digest};
    use ripemd160::Ripemd160;

    fn single_sha256(data: &[u8]) -> [u8; 32] {
        let sha = Sha256::digest(data);
        let mut arr = [0; 32];
        arr.copy_from_slice(&sha[..]);
        arr
    }

    fn double_sha256(data: &[u8]) -> [u8; 32] {
        let sha = Sha256::digest(data);
        let sha = Sha256::digest(&sha[..]);
        let mut arr = [0; 32];
        arr.copy_from_slice(&sha[..]);
        arr
    }

    fn hash160(data: &[u8]) -> [u8; 20] {
        let mut arr = [0; 20];
        arr.copy_from_slice(&Ripemd160::digest(&Sha256::digest(data)));
        arr
    }

    impl PublicKey for secp256k1::PublicKey {
        fn serialize(&self) -> [u8; 33] {
            secp256k1::PublicKey::serialize(self)
        }
    }

    impl Signature for secp256k1::Signature {
        fn serialize_der(&self) -> Vec<u8> {
            secp256k1::Signature::serialize_der(self)
        }
    }

    impl SecretKey for secp256k1::SecretKey {
        fn from_slice(slice: &[u8]) -> Result<Self, Box<std::error::Error>> {
            Ok(secp256k1::SecretKey::from_slice(slice)?)
        }
    }

    struct CryptoSecp256k1 {
        secp256k1: secp256k1::Secp256k1<secp256k1::All>
    }

    impl Crypto for CryptoSecp256k1 {
        type SecretKey=secp256k1::SecretKey;
        type PublicKey=secp256k1::PublicKey;
        type Signature=secp256k1::Signature;

        fn hash160(data: &[u8]) -> [u8; 20] {
            hash160(data)
        }

        fn single_sha256(data: &[u8]) -> [u8; 32] {
            single_sha256(data)
        }

        fn double_sha256(data: &[u8]) -> [u8; 32] {
            double_sha256(data)
        }

        fn sign(&self, message: &[u8], key: &Self::SecretKey) -> Self::Signature {
            self.secp256k1.sign(&secp256k1::Message::from_slice(message).unwrap(), key)
        }

        fn secret_to_pub_key(&self, key: &secp256k1::SecretKey) -> secp256k1::PublicKey {
            secp256k1::PublicKey::from_secret_key(&self.secp256k1, key)
        }
    }
}
