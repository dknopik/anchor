//! THIS CRATE IS NOT READY FOR PRODUCTION USE! DO *NOT* USE IN PRODUCTION CODE!
// from https://github.com/herumi/mcl/blob/3462cf0983bffb703a6e9f4623e47a26ec6e7fe5/include/mcl/lagrange.hpp

use blst::min_pk::{SecretKey, Signature};
use blst::*;
use rand::prelude::*;
use std::iter::{once, repeat_with};
use std::mem::MaybeUninit;
use std::num::NonZeroU64;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    InvalidThreshold,
    IntermediateOperationFailed,
    LessThanTwoSignatures,
    NotOneIdPerSignature,
    ZeroId,
    RepeatedId,
}

#[derive(Debug, Clone)]
pub struct KeyId {
    id: blst_fr,
}

impl From<u64> for KeyId {
    fn from(value: u64) -> Self {
        unsafe {
            let mut id = blst_fr::default();
            blst_fr_from_uint64(&mut id, &value);
            KeyId { id }
        }
    }
}

#[inline]
fn key_to_fr(key: &SecretKey) -> blst_fr {
    let mut key_fr = MaybeUninit::<blst_fr>::uninit();
    unsafe {
        blst_fr_from_scalar(key_fr.as_mut_ptr(), <&blst_scalar>::from(key));
        key_fr.assume_init()
    }
}

pub fn split(
    key: &SecretKey,
    threshold: NonZeroU64,
    total: NonZeroU64,
) -> Result<Vec<(KeyId, SecretKey)>, Error> {
    let threshold = threshold.get();
    let total = total.get();
    if threshold > total {
        return Err(Error::InvalidThreshold);
    }
    if threshold == 1 {
        return Ok(vec![(0.into(), key.clone()); total as usize]);
    }

    let rng = &mut thread_rng();
    let msk = once(key_to_fr(key))
        .chain(repeat_with(|| key_to_fr(&random_key(rng))).take((threshold - 1) as usize))
        .collect::<Vec<_>>();
    (1..=total)
        .map(|id| {
            let mut intermediate = MaybeUninit::<blst_fr>::uninit();
            let id: KeyId = id.into();
            unsafe {
                let mut y = msk.last().copied().unwrap();
                for i in (0..=(threshold - 2)).rev() {
                    blst_fr_mul(intermediate.as_mut_ptr(), &y, &id.id);
                    blst_fr_add(&mut y, intermediate.as_ptr(), &msk[i as usize]);
                }
                let mut scalar = blst_scalar::default();
                blst_scalar_from_fr(&mut scalar, &y);
                Ok((id, SecretKey::from_scalar_unchecked(scalar)))
            }
        })
        .collect()
}

fn recover_signature_v1(signatures: &[Signature], ids: &[KeyId]) -> Result<Signature, Error> {
    if signatures.len() < 2 {
        return Err(Error::LessThanTwoSignatures);
    }
    if signatures.len() != ids.len() {
        return Err(Error::NotOneIdPerSignature);
    }

    // intermediates. todo: maybe we can get rid of i2?
    let mut i1 = MaybeUninit::<blst_fr>::uninit();
    let mut i2 = MaybeUninit::<blst_fr>::uninit();
    let mut is = MaybeUninit::<blst_scalar>::uninit();

    let zero = unsafe {
        blst_fr_from_uint64(i1.as_mut_ptr(), &0);
        i1.assume_init()
    };

    let mut a = ids[0].clone().id;
    unsafe {
        for id in &ids[1..] {
            blst_fr_mul(i1.as_mut_ptr(), &a, &id.id);
            a = i1.assume_init()
        }
    }
    if a == zero {
        return Err(Error::ZeroId);
    }

    let mut d = Vec::with_capacity(ids.len() * 32);
    for id_i in ids {
        for id_j in ids.iter() {
            if id_i as *const KeyId != id_j as *const KeyId {
                unsafe {
                    blst_fr_sub(i1.as_mut_ptr(), &id_j.id, &id_i.id);
                    if i1.assume_init_ref() == &zero {
                        return Err(Error::RepeatedId);
                    }
                    blst_fr_mul(i2.as_mut_ptr(), &id_i.id, i1.as_ptr());
                    // todo we might have to check that another_intermediate != 0 before inversing
                    blst_fr_inverse(i1.as_mut_ptr(), i2.as_ptr());
                    blst_fr_mul(i2.as_mut_ptr(), i1.as_ptr(), &a);
                    blst_scalar_from_fr(is.as_mut_ptr(), i2.as_ptr());
                    d.extend(is.assume_init_ref().b);
                }
            }
        }
    }

    /*let signatures = signatures.iter().map(|(_, signature)| {
        let mut p2 = MaybeUninit::<blst_p2>::uninit();
        unsafe {
            blst_p2_from_affine(p2.as_mut_ptr(), signature.into());
            p2.assume_init()
        }
    }).collect::<Vec<_>>();

    let result = MaybeUninit::<blst_p2>::uninit();
    unsafe {
        blst_p2_unchecked_mult()
    }


    Ok(unsafe { result.assume_init() })*/

    Ok(signatures.mult(&d, 255).to_signature())
}

fn recover_signature_v2(signatures: &[Signature], ids: &[KeyId]) -> Result<Signature, Error> {
    if signatures.len() < 2 {
        return Err(Error::LessThanTwoSignatures);
    }
    if signatures.len() != ids.len() {
        return Err(Error::NotOneIdPerSignature);
    }

    // intermediates. todo: maybe we can get rid of i2?
    let mut fr_1 = MaybeUninit::<blst_fr>::uninit();
    let mut fr_2 = MaybeUninit::<blst_fr>::uninit();
    let mut s = MaybeUninit::<blst_scalar>::uninit();
    let mut p2_1 = MaybeUninit::<blst_p2>::uninit();
    let mut p2_2 = MaybeUninit::<blst_p2>::uninit();
    let mut p2a = MaybeUninit::<blst_p2_affine>::uninit();

    let zero = unsafe {
        blst_fr_from_uint64(fr_1.as_mut_ptr(), &0);
        fr_1.assume_init()
    };

    let mut a = ids[0].clone().id;
    unsafe {
        for id in &ids[1..] {
            blst_fr_mul(fr_1.as_mut_ptr(), &a, &id.id);
            a = fr_1.assume_init()
        }
    }
    if a == zero {
        return Err(Error::ZeroId);
    }

    let mut first = false;
    let mut result = MaybeUninit::<blst_p2>::uninit();
    for (id_i, sig_i) in ids.iter().zip(signatures) {
        for id_j in ids {
            if id_i as *const KeyId != id_j as *const KeyId {
                unsafe {
                    blst_fr_sub(fr_1.as_mut_ptr(), &id_j.id, &id_i.id);
                    if fr_1.assume_init_ref() == &zero {
                        return Err(Error::RepeatedId);
                    }
                    blst_fr_mul(fr_2.as_mut_ptr(), &id_i.id, fr_1.as_ptr());
                    // todo we might have to check that fr_2 != 0 before inversing
                    blst_fr_inverse(fr_1.as_mut_ptr(), fr_2.as_ptr());
                    blst_fr_mul(fr_2.as_mut_ptr(), fr_1.as_ptr(), &a);
                    blst_scalar_from_fr(s.as_mut_ptr(), fr_2.as_ptr());
                    blst_p2_from_affine(p2_1.as_mut_ptr(), <&blst_p2_affine>::from(sig_i));
                    blst_p2_mult(p2_2.as_mut_ptr(), p2_1.as_ptr(), s.as_ptr() as *const u8, 255);
                    if first {
                        result.write(p2_2.assume_init());
                        first = false;
                    } else {
                        blst_p2_add(p2_1.as_mut_ptr(), result.as_ptr(), p2_2.as_ptr());
                        result.write(p2_1.assume_init());
                    }
                }
            }
        }
    }

    unsafe {
        blst_p2_to_affine(p2a.as_mut_ptr(), result.as_ptr());
        Ok(p2a.assume_init().into())
    }
}

// TODO: SECURE RANDOMNESS!!!
fn random_key(rng: &mut ThreadRng) -> SecretKey {
    let ikm: [u8; 32] = rng.gen();
    SecretKey::key_gen(&ikm, &[]).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    #[test]
    fn test_basic_often() {
        for _ in 0..100 {
            test_basic();
        }
    }

    fn test_basic() {
        let rng = &mut thread_rng();
        let total = rng.gen_range(2..=13);
        let threshold = rng.gen_range(2..=total);

        let master = random_key(rng);
        let pk = master.sk_to_pk();

        let mut keys = split(
            &master,
            NonZeroU64::new(threshold as u64).unwrap(),
            NonZeroU64::new(total as u64).unwrap(),
        )
        .unwrap();

        // shuffle to sign with varying key indices
        keys.shuffle(rng);

        let (ids, keys): (Vec<_>, Vec<_>) = keys.into_iter().unzip();

        assert_eq!(keys.len(), total);

        let mut data = [0u8; 1024];
        rng.fill(&mut data);

        let signers = rng.gen_range(2..=threshold);

        let signatures = keys
            .into_iter()
            .take(signers)
            .map(|key| key.sign(&data, DST, &[]))
            .collect::<Vec<_>>();

        let aggregate_v1 = recover_signature_v1(&signatures, &ids[..signers]).unwrap();
        let aggregate_v2 = recover_signature_v2(&signatures, &ids[..signers]).unwrap();

        let result = aggregate_v1.verify(true, &data, DST, &[], &pk, false);
        if signers >= threshold {
            assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
        } else {
            assert_eq!(result, BLST_ERROR::BLST_VERIFY_FAIL);
        }
    }
}
