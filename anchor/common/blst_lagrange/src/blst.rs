// from https://github.com/herumi/mcl/blob/3462cf0983bffb703a6e9f4623e47a26ec6e7fe5/include/mcl/lagrange.hpp
use crate::Error;
use bls::Signature;
use blst::min_pk::SecretKey;
use blst::*;
use rand::prelude::*;
use std::iter::{once, repeat_with};
use std::mem::MaybeUninit;
use std::num::NonZeroU64;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct KeyId {
    num: u64,
    fr: blst_fr,
}

impl TryFrom<u64> for KeyId {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Error> {
        if value != 0 {
            unsafe {
                let mut id = MaybeUninit::<blst_fr>::uninit();
                blst_fr_from_uint64(id.as_mut_ptr(), &value);
                Ok(KeyId {
                    num: value,
                    fr: id.assume_init(),
                })
            }
        } else {
            Err(Error::ZeroId)
        }
    }
}
impl From<NonZeroU64> for KeyId {
    fn from(value: NonZeroU64) -> Self {
        unsafe {
            let mut id = MaybeUninit::<blst_fr>::uninit();
            blst_fr_from_uint64(id.as_mut_ptr(), &value.get());
            KeyId {
                num: value.get(),
                fr: id.assume_init(),
            }
        }
    }
}

impl From<KeyId> for u64 {
    fn from(value: KeyId) -> Self {
        value.num
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

pub fn split_with_rng(
    key: bls::SecretKey,
    threshold: u64,
    ids: impl IntoIterator<Item = KeyId>,
    rng: &mut (impl CryptoRng + Rng),
) -> Result<Vec<(KeyId, bls::SecretKey)>, Error> {
    let key = key.point();

    if threshold <= 1 {
        return Err(Error::InvalidThreshold);
    }

    // MaybeUninit needed to make `Zeroizing` work
    let msk = Zeroizing::new(
        once(Ok(MaybeUninit::new(key_to_fr(key))))
            .chain(
                repeat_with(|| random_key(rng).map(|sk| MaybeUninit::new(key_to_fr(sk.point()))))
                    .take((threshold - 1) as usize),
            )
            .collect::<Result<Vec<_>, _>>()?,
    );
    ids.into_iter()
        .map(|id| {
            let mut intermediate = MaybeUninit::<blst_fr>::uninit();
            unsafe {
                let mut y = (*msk).last().copied().unwrap();
                for i in (0..=(threshold - 2)).rev() {
                    blst_fr_mul(intermediate.as_mut_ptr(), y.as_ptr(), &id.fr);
                    blst_fr_add(
                        y.as_mut_ptr(),
                        intermediate.as_ptr(),
                        msk[i as usize].as_ptr(),
                    );
                }
                let mut scalar = blst_scalar::default();
                blst_scalar_from_fr(&mut scalar, y.as_ptr());
                Ok((
                    id,
                    bls::SecretKey::from_point(SecretKey::from_scalar_unchecked(scalar)),
                ))
            }
        })
        .collect()
}

#[cfg(not(feature = "blst_single_thread"))]
pub fn combine_signatures(signatures: &[Signature], ids: &[KeyId]) -> Result<Signature, Error> {
    if signatures.len() < 2 {
        return Err(Error::LessThanTwoSignatures);
    }
    if signatures.len() != ids.len() {
        return Err(Error::NotOneIdPerSignature);
    }

    let signatures = signatures
        .iter()
        .map(|sig| sig.point().cloned().ok_or(Error::InvalidSignature))
        .collect::<Result<Vec<_>, _>>()?;

    // intermediates.
    let mut ifr = MaybeUninit::<blst_fr>::uninit();
    let mut is = MaybeUninit::<blst_scalar>::uninit();

    let zero = unsafe {
        blst_fr_from_uint64(ifr.as_mut_ptr(), &0);
        ifr.assume_init()
    };

    let mut numerator = ids[0].clone().fr;
    unsafe {
        for id in &ids[1..] {
            blst_fr_mul(&mut numerator, &numerator, &id.fr);
        }
    }
    if numerator == zero {
        return Err(Error::ZeroId);
    }

    let mut d = Vec::with_capacity(ids.len() * 32);
    unsafe {
        for id_i in ids {
            let mut denominator = id_i.fr;
            for id_j in ids.iter() {
                if id_i as *const KeyId != id_j as *const KeyId {
                    blst_fr_sub(ifr.as_mut_ptr(), &id_j.fr, &id_i.fr);
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

    Ok(Signature::from_point(
        signatures.mult(&d, 255).to_signature(),
        false,
    ))
}

// variant not using blsts pooling, seems to be slower. might still make sense for us because we
// want to control threading
#[cfg(feature = "blst_single_thread")]
pub fn combine_signatures(signatures: &[Signature], ids: &[KeyId]) -> Result<Signature, Error> {
    if signatures.len() < 2 {
        return Err(Error::LessThanTwoSignatures);
    }
    if signatures.len() != ids.len() {
        return Err(Error::NotOneIdPerSignature);
    }

    let signatures = signatures
        .iter()
        .map(|sig| sig.point().cloned().ok_or(Error::InvalidSignature))
        .collect::<Result<Vec<_>, _>>()?;

    // intermediates.
    let mut ifr = MaybeUninit::<blst_fr>::uninit();
    let mut is = MaybeUninit::<blst_scalar>::uninit();
    let mut ip2 = MaybeUninit::<blst_p2>::uninit();
    let mut ip2a = MaybeUninit::<blst_p2_affine>::uninit();

    let zero = unsafe {
        blst_fr_from_uint64(ifr.as_mut_ptr(), &0);
        ifr.assume_init()
    };

    let mut numerator = ids[0].clone().fr;
    unsafe {
        for id in &ids[1..] {
            blst_fr_mul(&mut numerator, &numerator, &id.fr);
        }
    }
    if numerator == zero {
        return Err(Error::ZeroId);
    }

    let mut first = true;
    let mut result = MaybeUninit::<blst_p2>::uninit();
    unsafe {
        for (id_i, sig_i) in ids.iter().zip(&signatures) {
            let mut denominator = id_i.fr.clone();
            for id_j in ids.iter() {
                if id_i as *const KeyId != id_j as *const KeyId {
                    blst_fr_sub(ifr.as_mut_ptr(), &id_j.fr, &id_i.fr);
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
            blst_p2_mult(
                ip2.as_mut_ptr(),
                ip2.as_ptr(),
                &is.assume_init_ref().b as *const u8,
                255,
            );
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
        Ok(Signature::from_point(ip2a.assume_init().into(), false))
    }
}

pub(crate) fn random_key(rng: &mut (impl CryptoRng + Rng)) -> Result<bls::SecretKey, Error> {
    let ikm: [u8; 32] = rng.gen();
    let sk = SecretKey::key_gen(&ikm, &[]).map_err(|_| Error::InternalError)?;
    Ok(bls::SecretKey::from_point(sk))
}
