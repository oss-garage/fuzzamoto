//! BIP-330 (Erlay) transaction reconciliation primitives.
//!
//! Mirrors the derivations used by Bitcoin Core's `node/txreconciliation`, so programs can refer to
//! transactions by the short ids a target node computes for a given link and build sketches the
//! node can decode.

use bitcoin::{
    consensus::encode::{VarInt, serialize},
    hashes::{Hash, HashEngine, sha256, siphash24},
};

/// Tag of the tagged hash used to combine the two salts of a reconciliation link.
const RECON_STATIC_SALT: &str = "Tx Relay Salting";

/// Short ids are reduced modulo this value before adding one. A target built with
/// `bitcoin-core-erlay-collisions.patch` uses a tiny range so short id collisions are common.
const SHORT_ID_MODULUS: u64 = if cfg!(feature = "erlay_collisions") {
    0xFF
} else {
    0xFFFF_FFFF
};

/// Reduction polynomial of the GF(2^32) field used by 32-bit minisketches:
/// x^32 + x^7 + x^3 + x^2 + 1.
const FIELD_MODULUS: u32 = 0x8D;

/// `SipHash` keys shared by both ends of a reconciliation link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconKeys {
    pub k0: u64,
    pub k1: u64,
}

impl ReconKeys {
    /// Derive the link keys from the salts exchanged in `sendtxrcncl`. The order of the salts
    /// does not matter.
    #[must_use]
    pub fn from_salts(salt1: u64, salt2: u64) -> Self {
        let tag = sha256::Hash::hash(RECON_STATIC_SALT.as_bytes());
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array());
        engine.input(tag.as_byte_array());
        engine.input(&salt1.min(salt2).to_le_bytes());
        engine.input(&salt1.max(salt2).to_le_bytes());
        let full_salt = sha256::Hash::from_engine(engine).to_byte_array();

        Self {
            k0: u64::from_le_bytes(full_salt[0..8].try_into().unwrap()),
            k1: u64::from_le_bytes(full_salt[8..16].try_into().unwrap()),
        }
    }

    /// Short id of a transaction on this link. `wtxid` is in internal byte order.
    #[must_use]
    pub fn short_id(&self, wtxid: &[u8; 32]) -> u32 {
        let hash = siphash24::Hash::hash_to_u64_with_keys(self.k0, self.k1, wtxid);
        1 + u32::try_from(hash % SHORT_ID_MODULUS).expect("value is reduced below 2^32 - 1")
    }
}

/// Largest sketch capacity a program may build, twice Bitcoin Core's `MAX_SKETCH_CAPACITY` so
/// extensions of the largest accepted sketch can still be built.
pub const MAX_BUILT_SKETCH_CAPACITY: u32 = 2 * 8_192;

/// A set of transactions (by wtxid) and raw short ids on one side of a reconciliation link.
#[derive(Debug, Clone, Default)]
pub struct ReconSet {
    /// Wtxids in internal byte order
    pub wtxids: Vec<[u8; 32]>,
    pub short_ids: Vec<u32>,
}

impl ReconSet {
    #[must_use]
    pub fn short_ids(&self, keys: &ReconKeys) -> Vec<u32> {
        self.wtxids
            .iter()
            .map(|wtxid| keys.short_id(wtxid))
            .chain(self.short_ids.iter().copied())
            .collect()
    }

    /// `sketch` message payload carrying syndromes `first..first + capacity` of the set.
    #[must_use]
    pub fn sketch_payload(&self, keys: &ReconKeys, first: u32, capacity: u32) -> Vec<u8> {
        let capacity = capacity.min(MAX_BUILT_SKETCH_CAPACITY) as usize;
        let syndromes = sketch_syndromes(&self.short_ids(keys), first as usize, capacity);
        let mut payload = serialize(&VarInt(syndromes.len() as u64));
        payload.extend(syndromes);
        payload
    }

    /// `reconcildiff` message payload asking for the set's short ids.
    #[must_use]
    pub fn reconcildiff_payload(&self, keys: &ReconKeys, result: u8) -> Vec<u8> {
        let short_ids = self.short_ids(keys);
        let mut payload = vec![result];
        payload.extend(serialize(&VarInt(short_ids.len() as u64)));
        payload.extend(short_ids.iter().flat_map(|id| id.to_le_bytes()));
        payload
    }
}

fn gf_mul(mut a: u32, mut b: u32) -> u32 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        b >>= 1;
        let carry = a & 0x8000_0000 != 0;
        a <<= 1;
        if carry {
            a ^= FIELD_MODULUS;
        }
    }
    product
}

fn gf_pow(mut base: u32, mut exponent: u64) -> u32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

/// Serialized 32-bit minisketch of `capacity` syndromes containing `elements`, byte-for-byte
/// identical to libminisketch's output. Adding an element twice removes it again.
#[must_use]
pub fn sketch(elements: &[u32], capacity: usize) -> Vec<u8> {
    sketch_syndromes(elements, 0, capacity)
}

/// Syndromes `first..first + count` of the sketch of `elements`. A BIP-330 sketch extension is
/// `sketch_syndromes(elements, capacity, capacity)` for an initial sketch of `capacity`.
#[must_use]
pub fn sketch_syndromes(elements: &[u32], first: usize, count: usize) -> Vec<u8> {
    let mut syndromes = vec![0u32; count];
    for &element in elements {
        if element == 0 {
            continue;
        }
        let square = gf_mul(element, element);
        let mut power = gf_mul(element, gf_pow(square, first as u64));
        for syndrome in &mut syndromes {
            *syndrome ^= power;
            power = gf_mul(power, square);
        }
    }
    syndromes.iter().flat_map(|s| s.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wtxid_from_display_hex(hex: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        bytes.reverse();
        bytes
    }

    #[test]
    #[cfg(not(feature = "erlay_collisions"))]
    fn short_ids_collide_like_bitcoin_core() {
        // COLLIDING_WTXID{,_2} from Bitcoin Core PR 35591's txreconciliation_tests.cpp, which
        // collide on a link salted with (2, 1).
        let a = wtxid_from_display_hex(
            "fdfb332e93ecd3b28835f51f9d999278dba2c10fb45611229a17136a00a4d3c9",
        );
        let b = wtxid_from_display_hex(
            "8f16f117d30b68c6fcdd1ee033d2b4f8aba719088e5aff78c8f9536aeb1388b4",
        );
        let keys = ReconKeys::from_salts(2, 1);
        assert_eq!(keys, ReconKeys::from_salts(1, 2));
        assert_eq!(keys.short_id(&a), keys.short_id(&b));
        assert_ne!(
            ReconKeys::from_salts(3, 1).short_id(&a),
            ReconKeys::from_salts(3, 1).short_id(&b)
        );
    }

    #[test]
    fn sketches_match_libminisketch() {
        // Generated with libminisketch (bits=32, implementation=0) from Bitcoin Core's src/minisketch.
        let vectors: &[(usize, &[u32], &str)] = &[
            (1, &[0xa6fbc764], "64c7fba6"),
            (1, &[0x5a3d4d43, 0x546cccd5, 0x25079fe4], "721e562b"),
            (
                1,
                &[
                    0xfe544cf8, 0x563b0b93, 0x90292bb1, 0x1301479f, 0x92b3cb75, 0x301eb078,
                    0x6a9504bd, 0x781bbd2c, 0x14e09a29, 0xb53eb735, 0x831b1e3f, 0xf06df973,
                    0x7789fdb7, 0x447958c8, 0x16064c19, 0x0bd08a96, 0x9a2ce27e, 0xe8c74fed,
                    0x0706f802, 0x7a50f9e1,
                ],
                "09ec5768",
            ),
            (2, &[0xee261f06], "061f26eeb228ac42"),
            (2, &[0x6e7756da, 0x1110073e, 0x3913cf93], "779e7446ff34ea2f"),
            (
                2,
                &[
                    0x130c9ea7, 0x149c33e9, 0xff459731, 0x87d205a7, 0xccb205df, 0x39998518,
                    0x324c68fb, 0x9a867974, 0x360ac310, 0x5f6a3510, 0x0d807957, 0x2712cd55,
                    0xa338e8c4, 0xa6a88e8b, 0xdbeb284a, 0x1a701ace, 0x09dc8ffa, 0x3eebb13a,
                    0xd91dab7d, 0x3a7fe014,
                ],
                "f0cd4a715eedb74e",
            ),
            (5, &[0x755a19c2], "c2195a7568f31b2614e5ccfc4d26af7f85e7cc0c"),
            (
                5,
                &[0xffffffff, 0x85cff11b, 0xe1822c94],
                "7022b29b4585401fb498bd912eab2bdc02fe7c6d",
            ),
            (
                5,
                &[
                    0xc1354d97, 0xd749d2ac, 0xbdb6ef68, 0xfe774c9a, 0x2e9dae46, 0x2e3a8bd9,
                    0x879eea07, 0xf92a0f72, 0xd97a2f15, 0xfc28770e, 0x15f3f85f, 0xb0bc5af4,
                    0xa59fc7c2, 0xb0069430, 0x2ecc03ee, 0x5db7961f, 0xa41ce4ac, 0x3de98f7d,
                    0xa0f93113, 0xafbeb00a,
                ],
                "582ae35b4aed70998e47e04ad17d660b84a53d43",
            ),
            (
                16,
                &[0x9ad8d2d5],
                "d5d2d89aa176c8ac6ea2eaac65ca112ce513b3d11e951bc3351e7d002a9e0f20d6e73a56e4bb538ce1fa0dca03aa3580e43ee96a0315b5e8bd362513f5635aa7",
            ),
            (
                16,
                &[0x757ff170, 0xc605cbc9, 0xcf6f33b6],
                "0f09157ccfffb8dabb03e7d37e66aa218df26ee18368aa70b28f2300effcf117e6f8f2816c29b88d05082011663a3153f23d11695267d520e35952d717060154",
            ),
            (
                16,
                &[
                    0xe83c9a01, 0xb48de88a, 0x1b0a33a8, 0xa32d21f5, 0x6f3b1bf9, 0x8be10ed8,
                    0xfd1f2248, 0x6173c34d, 0xd21d3b8a, 0x43912d2d, 0xb60dfbee, 0x96ea8299,
                    0x120589ea, 0x8278e904, 0xe9c98ff2, 0x9225404c, 0x9030e2b8, 0x60b6a40f,
                    0x6effe34f, 0x70adac11,
                ],
                "9b5d0e28920f7b2f30ed469cc298c42360b78748cad076b481b64c60d9c5a13ee92b32b6c9e5d53905ca6ba12eecccec31c243016365bcb4fb62fd4392bab6a6",
            ),
        ];
        for (capacity, elements, expected) in vectors {
            let encoded: String = sketch(elements, *capacity)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(
                &encoded, expected,
                "capacity={capacity} elements={elements:x?}"
            );
        }
    }

    #[test]
    fn sketch_extension_is_upper_half() {
        let elements = [0xa6fb_c764, 3, 0xffff_ffff, 0x1234_5678];
        let mut extended = sketch(&elements, 5);
        extended.extend(sketch_syndromes(&elements, 5, 5));
        assert_eq!(extended, sketch(&elements, 10));
    }

    #[test]
    #[cfg(feature = "erlay_collisions")]
    fn short_ids_use_reduced_range() {
        let keys = ReconKeys::from_salts(0, 10_393_729_187_455_219_830);
        let ids: std::collections::HashSet<u32> =
            (0u8..=255).map(|i| keys.short_id(&[i; 32])).collect();
        assert!(ids.iter().all(|id| (1..=0xFF).contains(id)));
        // 256 wtxids cannot map to 255 distinct short ids.
        assert!(ids.len() < 256);
    }

    #[test]
    fn payloads_are_framed_like_bitcoin_core() {
        let keys = ReconKeys::from_salts(2, 1);
        let wtxid = wtxid_from_display_hex(
            "fdfb332e93ecd3b28835f51f9d999278dba2c10fb45611229a17136a00a4d3c9",
        );
        let set = ReconSet {
            wtxids: vec![wtxid],
            short_ids: vec![7],
        };
        let ids = [keys.short_id(&wtxid), 7];
        assert_eq!(set.short_ids(&keys), ids);

        let mut sketch_msg = vec![8];
        sketch_msg.extend(sketch(&ids, 2));
        assert_eq!(set.sketch_payload(&keys, 0, 2), sketch_msg);
        assert_eq!(
            set.sketch_payload(&keys, 2, 2)[1..],
            sketch_syndromes(&ids, 2, 2)[..]
        );
        assert_eq!(
            set.sketch_payload(&keys, 0, u32::MAX).len(),
            5 + 4 * MAX_BUILT_SKETCH_CAPACITY as usize
        );

        let mut diff = vec![1, 2];
        diff.extend(ids[0].to_le_bytes());
        diff.extend(7u32.to_le_bytes());
        assert_eq!(set.reconcildiff_payload(&keys, 1), diff);
    }

    #[test]
    fn sketch_elements_cancel() {
        assert_eq!(sketch(&[7, 9, 7], 4), sketch(&[9], 4));
        assert_eq!(sketch(&[], 3), vec![0; 12]);
    }
}
