/// shamir.rs — Shamir's Secret Sharing (256-bit threshold scheme).
///
/// This implementation treats a 32-byte key as 32 separate secrets, 
/// each shared using a polynomial over GF(2^8).

use crate::{Result, MindLockError};
use crate::format::KeyShard;
use crate::crypto::{DerivedKey, KEY_LEN, SALT_LEN};
use rand::RngCore;

/// Split a 32-byte master key into N shards with threshold K.
pub fn split_key(key: &DerivedKey, threshold: u8, total: u8) -> Result<Vec<KeyShard>> {
    if threshold == 0 || threshold > total {
        return Err(MindLockError::KeyDerivation("Invalid shard threshold".into()));
    }

    // shamir crate expects a byte slice
    let data = &key.key_bytes;
    
    // We create a shard set. Each shard contains (x, y_at_x) for each byte.
    // Index 0 is reserved for the secret itself (y-intercept).
    let mut shards = Vec::with_capacity(total as usize);
    for i in 1..=total {
        shards.push(KeyShard {
            index: i,
            data: vec![0u8; KEY_LEN],
        });
    }

    // For each of the 32 bytes in the key...
    for byte_idx in 0..KEY_LEN {
        let secret_byte = data[byte_idx];
        
        // Generate polynomial coefficients: a0 + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
        // a0 is the secret byte.
        let mut poly = vec![0u8; threshold as usize];
        poly[0] = secret_byte;
        rand::thread_rng().fill_bytes(&mut poly[1..]);

        // Evaluate polynomial at x = 1..N
        for x in 1..=total {
            shards[(x-1) as usize].data[byte_idx] = evaluate_poly(&poly, x);
        }
    }

    Ok(shards)
}

/// Reconstruct a 32-byte key from at least K shards.
pub fn combine_shards(shards: &[KeyShard], threshold: u8, salt: [u8; SALT_LEN]) -> Result<DerivedKey> {
    if shards.len() < threshold as usize {
        return Err(MindLockError::KeyDerivation(format!(
            "Insufficient shards: need {}, got {}", threshold, shards.len()
        )));
    }

    let mut key_bytes = [0u8; KEY_LEN];

    // For each of the 32 bytes...
    for byte_idx in 0..KEY_LEN {
        // Prepare points (x, y) for Lagrange interpolation
        let mut points = Vec::with_capacity(shards.len());
        for s in shards {
            points.push((s.index, s.data[byte_idx]));
        }
        
        // Interpolate at x=0 to get the secret byte
        key_bytes[byte_idx] = interpolate_at_zero(&points);
    }

    Ok(DerivedKey { key_bytes, salt })
}

// ── Galois Field (2^8) Math ──────────────────────────────────────────────────
// Using primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)

const GF_ORDER: usize = 256;

lazy_static::lazy_static! {
    static ref EXP: [u8; 512] = {
        let mut exp = [0u8; 512];
        let mut x = 1u16;
        for i in 0..255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        exp
    };
    static ref LOG: [u8; 256] = {
        let mut log = [0u8; 256];
        for i in 0..255 {
            log[EXP[i] as usize] = i as u8;
        }
        log
    };
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 { return 0; }
    let idx = (LOG[a as usize] as usize) + (LOG[b as usize] as usize);
    EXP[idx]
}

fn gf_div(a: u8, b: u8) -> u8 {
    if a == 0 { return 0; }
    if b == 0 { panic!("GF(2^8) division by zero"); }
    let idx = (LOG[a as usize] as usize) + 255 - (LOG[b as usize] as usize);
    EXP[idx]
}

fn evaluate_poly(poly: &[u8], x: u8) -> u8 {
    if x == 0 { return poly[0]; }
    let mut y = 0u8;
    let mut x_pow = 1u8;
    for &coeff in poly {
        y ^= gf_mul(coeff, x_pow);
        x_pow = gf_mul(x_pow, x);
    }
    y
}

fn interpolate_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut secret = 0u8;
    for i in 0..points.len() {
        let (xi, yi) = points[i];
        let mut li = 1u8;
        for j in 0..points.len() {
            if i == j { continue; }
            let (xj, _) = points[j];
            // numerator: (0 - xj) = xj in GF(2^8)
            // denominator: (xi - xj)
            let num = xj;
            let den = xi ^ xj;
            li = gf_mul(li, gf_div(num, den));
        }
        secret ^= gf_mul(yi, li);
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_roundtrip() {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(b"this is a 32-byte secret key-!!");
        let salt = [0u8; 32];
        let original = DerivedKey { key_bytes, salt };

        let shards = split_key(&original, 3, 5).unwrap();
        assert_eq!(shards.len(), 5);

        // Success with 3 shards
        let combined = combine_shards(&shards[0..3], 3, salt).unwrap();
        assert_eq!(combined.key_bytes, original.key_bytes);

        // Success with different 3 shards
        let combined2 = combine_shards(&[shards[0].clone(), shards[2].clone(), shards[4].clone()], 3, salt).unwrap();
        assert_eq!(combined2.key_bytes, original.key_bytes);

        // Failure with 2 shards (should produce deterministic but incorrect output in some cases, 
        // but our implementation should return error if length < threshold)
        let result = combine_shards(&shards[0..2], 3, salt);
        assert!(result.is_err());
    }
}
