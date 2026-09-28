//! Test-only signers and signature vectors. The only file under `src/` that
//! may name `SigningKey` (docs/PHASE3_DESIGN.md §3.3); `lib.rs` compiles it
//! only for tests.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

use crate::sig::KEY_LEN;
use crate::SIG_LEN;

/// A deterministic P-256 test identity key (secret scalar `[seed; 32]`) and
/// its SEC1 uncompressed public key.
pub(crate) struct TestKey {
    key: SigningKey,
    pub(crate) public: [u8; KEY_LEN],
}

impl TestKey {
    pub(crate) fn new(seed: u8) -> TestKey {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        TestKey { key, public }
    }

    /// Raw r ‖ s over `msg` (RFC 6979, S as it comes).
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; SIG_LEN] {
        let sig: Signature = self.key.sign(msg);
        sig.to_bytes().into()
    }

    /// The public key in SEC1 compressed form (33 bytes).
    pub(crate) fn compressed(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec()
    }
}

/// One signature made by Security.framework in the Phase 3 spike
/// (tools/verify/spikes/p3/sigspike: `SecKeyCreateSignature` with
/// `.ecdsaSignatureDigestX962SHA256` over SHA-256 of `msg`, which is what
/// Brev's Swift side does). Copied from `tools/verify/spikes/p3/vectors.txt`.
pub(crate) struct Vector {
    pub(crate) name: &'static str,
    /// s > n / 2, as the signer produced it.
    pub(crate) high_s: bool,
    key: &'static str,
    msg: &'static str,
    der: &'static str,
}

impl Vector {
    pub(crate) fn key(&self) -> Vec<u8> {
        unhex(self.key)
    }
    pub(crate) fn msg(&self) -> Vec<u8> {
        unhex(self.msg)
    }
    pub(crate) fn der(&self) -> Vec<u8> {
        unhex(self.der)
    }
}

/// Software key low-S, software key high-S, Secure Enclave key high-S, and
/// a 69-byte DER (Secure Enclave, a 31-byte s).
pub(crate) const VECTORS: [Vector; 4] = [
    Vector {
        name: "software, digest, low-S",
        high_s: false,
        key: "04647c953c1869140f3e96298737a01cc4f8061bb03cf7d16a059a86b58692a1dfb6eec46f73b74ec5a97a10986238c85e745747b6004ba178db2ee7b3bbf580d8",
        msg: "baa5ffb9122d7a00d270e361d11e437aceb2949bbc6809c25c0507caf45e7e14ff3f865c3492e12dd228bf8d2df5c3898561c5211eadd8a97dc99813782ece44c688ca25e8e00e12a4ac937a4665808893044ba3e099a8c877df4156139cf9a0be56b59ed027ff33ca93a4b911b288fb6e77591aa960443a974c2c097665e9886707b705f29a87d10566dafde04c8832bf73793d4f89aa4b8de29df3190e2c7700017121636f19bf5188662d7e16006ab237bc9441b86d9ac53402a1890910bf77cea5b50da22d61a4d40241896046e53965a7f227e3de41fbb5e5adaaf168beff34b14944d76dbb4c22d6abe56e707e1d98ab9a4a34e556d1c643c4ce378b139a3b86ac5fc8b532fcb3914cc6c9076134003f8b226e7b017a153f49d476973ac38186ca0ac08ff63e795b14cd5741740c6868a355fb96cfbbc48d2d3746703370a8dd81920c5510e3dc48132d71c0382041c8056d802d53ebb5d26d439b9ec2533a1267b3d12bc7a2b2f3df63d5",
        der: "30440220293131cec777059a6d0e20cf3519e92e3ccbeba57277e245ed0eda7d6943e7fb022028d04f6ec571e39c3e569b0d2e0fa353244386c84a0b5ca6b6a0b6b9f649308d",
    },
    Vector {
        name: "software, digest, high-S",
        high_s: true,
        key: "04647c953c1869140f3e96298737a01cc4f8061bb03cf7d16a059a86b58692a1dfb6eec46f73b74ec5a97a10986238c85e745747b6004ba178db2ee7b3bbf580d8",
        msg: "3fb69c669cf1c19212c0b06ab16fa40de40a39c85253bd11f5943345be120f1bb0036bb45ca8255a2fb5e28212873e359d0226b3519ea641ef226fa601a3c141842aeaa05695b934a84e915fbba99d791344f05f413b59544c271e445041c7a5e893516fe51e5ca7b145a9dc9ccb0fc8a7dbfcc9b4ccf1d246cad50b4a2d1a055760c3fb3c187e637c6d94be2e1abfa6af0d9abcee156cf62a6cab742e4b0662fb0c99c76a08b93b04331aea350b2640a1d7a45a194a9a751bd27038a37e9dd7b8d31df2e055f2dbf9bbce5d18a6ec67aa9b2bc0b1741f585b62fd5b8d57c6edf3ae018f36cda27ae5390c4600d1604f38ee969b458d93cde51339041355d69d7f6331f6c86122e67fcaa3382157b90ab6fc080818dc5b71d7e49bf5462f7f632ff8545481041e5af20b2b9b405357c08dfd9c75b82a3f4bb36e30b7788711eb29792b9b9c606a1956f7bb28de7c058a3b52fe40a8dd212e2e4e20065bc770437487f0d286f1652b03623d4e840d",
        der: "3046022100a42159687958ecaa9b6b43198261d4478ad5ddc57c39a49c25fb33cf2214af12022100f4db317e4c092d42f4da589b7d966cd2844d8b0a8cf18d9282de2f0ed5895571",
    },
    Vector {
        name: "Secure Enclave, digest, high-S",
        high_s: true,
        key: "041b62c97504eabe5ace4003ca8cd4e6e7a1a396fe4e32668b7edc85deaec7126b3af4d6bda69b94b5b55da924796611bd742d06c91eab4d3a39952727acf05b61",
        msg: "da0f220e56b9c2fbd95b3aa74679ebf7615c1693894c51c313875ab5cd9be6a7b17100c2e725b1cee56b53267040ad49a2da71822e565040a21b9087591dbfa485f6efbfff01a52032ff33c3525930ea5316fdfdd58f17c5806aaa5d11836d1aa014c33a1e191e4fb14a18be37c3af3b16b4d8cf8d806831de10aff8c7e4a481eb1bf3287519493356ee2652378e95ac65b143088094b462cbefe204ab0b5f4b0a48d568cbe5ef666e931363025afbc2fb80b7ce4c955341e8e9fce7166d7763eaf96308a48f37a7c75ad4208112e904a0872fa2ad447646d413a7d34133403259e889a27c3e744fefd21175d33e3e7d7238914d52702b9727c43321f4e96834c9829493293d39fb4968c4ac8f6df37855c2479799fe916192ea1160ea642431e3c675aedce0db8cd75913c040b0390cad0095d55171d4586168860dd02fc61d005f7996dd8eba39174705af03078007418570ea49a2af0f829d48b3067aef20c3feee12c8482aea8ee99913cd9a",
        der: "304602210080568bd427e03807181ba0e6fa5eaa2ca967d99b25742f051b58a8da01aa723502210095345ba8bbef6f9607b41899470d3fdbe7e02d54c1c4261a68af26455adbd612",
    },
    Vector {
        name: "Secure Enclave, digest, 69-byte DER",
        high_s: false,
        key: "041b62c97504eabe5ace4003ca8cd4e6e7a1a396fe4e32668b7edc85deaec7126b3af4d6bda69b94b5b55da924796611bd742d06c91eab4d3a39952727acf05b61",
        msg: "c8a834f2ad8fdb8b841fb9ee4de75e0c3d93b0a6128e13e2f9faf4469f2061bac32b1c1cb2912f4d02e61608353a48271d923f543788988ee7ac830afd14a985f29de84d710ea871f5ca324ddc521e457a803f03657419f8ef21b46529d909150e8637f689c38eb55a0e888e9a7c6e7f752b6e900eab25917fd819e73fcebc1e5d84c3442a04d5732b3a4e6624bd7900674be525fb5cee3a1306eac73a51ccbf741c3dfba957f7b962edc89539bd1604b2c7b9c9f0b774424a9e0ee84c1332eb5fb1b4f4236c793cf89d07b49fcbb641d281245cfecdf2f33165453fd7e6a9fd6530fe73b88aa05d46d9c75fa8cfb71b8c756a874fcaa213b7b37dc572b1c018a0d4881a4bb6dd1a2187d48d9f3e4643b81ae5afe9c783d302ff9d9e4336bb6d7aae1b3c1de14fae0c45ce5d745583cc1ea9c53e7ece74fc8ee5183c660ac2af94904be400f4099a8f9f405dc4de13c8c107dac047737c2cb7dbc72ef92290913d5c204e07389bd16986ea86e729",
        der: "30430220493a521bec2835cf32b52756741cd702c5151f6f113ae0e8d8acf6a6cb851219021f17d1e068e3002a5bc5401bc9b85888408499c2cc990cb52eab573342362d73",
    },
];

pub(crate) fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
