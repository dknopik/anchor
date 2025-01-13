//! THIS CRATE IS NOT READY FOR PRODUCTION USE! DO *NOT* USE IN PRODUCTION CODE!
// from https://github.com/herumi/mcl/blob/3462cf0983bffb703a6e9f4623e47a26ec6e7fe5/include/mcl/lagrange.hpp
//#![feature(test)]
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

fn recover_signature(signatures: &[Signature], ids: &[KeyId]) -> Result<Signature, Error> {
    if signatures.len() < 2 {
        return Err(Error::LessThanTwoSignatures);
    }
    if signatures.len() != ids.len() {
        return Err(Error::NotOneIdPerSignature);
    }

    // intermediates.
    let mut ifr = MaybeUninit::<blst_fr>::uninit();
    let mut is = MaybeUninit::<blst_scalar>::uninit();

    let zero = unsafe {
        blst_fr_from_uint64(ifr.as_mut_ptr(), &0);
        ifr.assume_init()
    };

    let mut numerator = ids[0].clone().id;
    unsafe {
        for id in &ids[1..] {
            blst_fr_mul(&mut numerator, &numerator, &id.id);
        }
    }
    if numerator == zero {
        return Err(Error::ZeroId);
    }

    let mut d = Vec::with_capacity(ids.len() * 32);
    unsafe {
        for id_i in ids {
            let mut denominator = id_i.id.clone();
            for id_j in ids.iter() {
                if id_i as *const KeyId != id_j as *const KeyId {
                    blst_fr_sub(ifr.as_mut_ptr(), &id_j.id, &id_i.id);
                    if ifr.assume_init_ref() == &zero {
                        return Err(Error::RepeatedId);
                    }
                    blst_fr_mul(&mut denominator, &denominator, ifr.as_ptr());
                }
            }
            blst_fr_inverse(&mut denominator, &denominator);
            blst_fr_mul(ifr.as_mut_ptr(), &denominator, &numerator);
            blst_scalar_from_fr(is.as_mut_ptr(), ifr.as_ptr());
            d.extend(is.assume_init_ref().b);
        }
    }

    Ok(signatures.mult(&d, 255).to_signature())
}

// variant not using blsts pooling, seems to be slower
/*fn recover_signature(signatures: &[Signature], ids: &[KeyId]) -> Result<Signature, Error> {
    if signatures.len() < 2 {
        return Err(Error::LessThanTwoSignatures);
    }
    if signatures.len() != ids.len() {
        return Err(Error::NotOneIdPerSignature);
    }

    // intermediates.
    let mut ifr = MaybeUninit::<blst_fr>::uninit();
    let mut is = MaybeUninit::<blst_scalar>::uninit();
    let mut ip2 = MaybeUninit::<blst_p2>::uninit();
    let mut ip2a = MaybeUninit::<blst_p2_affine>::uninit();

    let zero = unsafe {
        blst_fr_from_uint64(ifr.as_mut_ptr(), &0);
        ifr.assume_init()
    };

    let mut numerator = ids[0].clone().id;
    unsafe {
        for id in &ids[1..] {
            blst_fr_mul(&mut numerator, &numerator, &id.id);
        }
    }
    if numerator == zero {
        return Err(Error::ZeroId);
    }

    let mut first = true;
    let mut result = MaybeUninit::<blst_p2>::uninit();
    unsafe {
        for (id_i, sig_i) in ids.iter().zip(signatures) {
            let mut denominator = id_i.id.clone();
            for id_j in ids.iter() {
                if id_i as *const KeyId != id_j as *const KeyId {
                    blst_fr_sub(ifr.as_mut_ptr(), &id_j.id, &id_i.id);
                    if ifr.assume_init_ref() == &zero {
                        return Err(Error::RepeatedId);
                    }
                    blst_fr_mul(&mut denominator, &denominator, ifr.as_ptr());
                }
            }
            blst_fr_inverse(&mut denominator, &denominator);
            blst_fr_mul(ifr.as_mut_ptr(), &denominator, &numerator);
            blst_scalar_from_fr(is.as_mut_ptr(), ifr.as_ptr());
            blst_p2_from_affine(ip2.as_mut_ptr(), <&blst_p2_affine>::from(sig_i));
            blst_p2_mult(ip2.as_mut_ptr(), ip2.as_ptr(), &is.assume_init_ref().b as *const u8, 255);
            if first {
                result.write(ip2.assume_init());
                first = false;
            } else {
                blst_p2_add(result.as_mut_ptr(), result.as_ptr(), ip2.as_ptr());
            }
        }
    }

    unsafe {
        blst_p2_to_affine(ip2a.as_mut_ptr(), result.as_ptr());
        Ok(ip2a.assume_init().into())
    }
}*/

// TODO: SECURE RANDOMNESS!!!
fn random_key(rng: &mut ThreadRng) -> SecretKey {
    let ikm: [u8; 32] = rng.gen();
    SecretKey::key_gen(&ikm, &[]).unwrap()
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::time::Instant;
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

        let signers = rng.gen_range(2..=total);

        let signatures = keys
            .into_iter()
            .take(signers)
            .map(|key| key.sign(&data, DST, &[]))
            .collect::<Vec<_>>();

        let aggregate = recover_signature(&signatures, &ids[..signers]).unwrap();

        let result = aggregate.verify(true, &data, DST, &[], &pk, false);
        if signers >= threshold {
            assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
        } else {
            assert_eq!(result, BLST_ERROR::BLST_VERIFY_FAIL);
        }
    }

    #[test]
    fn bench_basic() {
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

        let signers = rng.gen_range(2..=total);

        let signatures = keys
            .into_iter()
            .take(signers)
            .map(|key| key.sign(&data, DST, &[]))
            .collect::<Vec<_>>();

        let timing = Instant::now();
        for _ in 0..10_000 {
            black_box(recover_signature(&signatures, &ids[..signers]).unwrap());
        }
        println!("took {} ms", timing.elapsed().as_millis());

        /*let result = aggregate.verify(true, &data, DST, &[], &pk, false);
        if signers >= threshold {
            assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
        } else {
            assert_eq!(result, BLST_ERROR::BLST_VERIFY_FAIL);
        }*/
    }
}
