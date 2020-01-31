use super::*;

pub trait AesMode {
    fn reset(&mut self, iv: &[u8]);
}

impl<T: BlockEncryptor, X: PaddingProcessor> AesMode for EcbEncryptor<T, X> {
    fn reset(&mut self, _: &[u8]) {
        EcbEncryptor::reset(self)
    }
}

impl<T: BlockEncryptor, X: PaddingProcessor> AesMode for CbcEncryptor<T, X> {
    fn reset(&mut self, iv: &[u8]) {
        CbcEncryptor::reset(self, iv)
    }
}
impl<T: BlockDecryptor, X: PaddingProcessor> AesMode for EcbDecryptor<T, X> {
    fn reset(&mut self, _: &[u8]) {
        EcbDecryptor::reset(self)
    }
}

impl<T: BlockDecryptor, X: PaddingProcessor> AesMode for CbcDecryptor<T, X> {
    fn reset(&mut self, iv: &[u8]) {
        CbcDecryptor::reset(self, iv)
    }
}

pub struct EcbReader<T: BlockDecryptor, X: PaddingProcessor, R: Read>(
    AesReader<EcbDecryptor<T, X>, R>,
);
pub struct CbcReader<T: BlockDecryptor, X: PaddingProcessor, R: Read>(
    AesReader<CbcDecryptor<T, X>, R>,
);

impl<T: BlockDecryptor, X: PaddingProcessor, R: Read> EcbReader<T, X, R> {
    pub fn new(reader: R, algo: T, padding: X) -> Result<EcbReader<T, DecPadding<X>, R>> {
        let bs = algo.block_size();
        AesReader::new(reader, EcbDecryptor::new(algo, padding), bs).map(|a| Self(a))
    }
}
impl<T: BlockDecryptor, X: PaddingProcessor, R: Read> CbcReader<T, X, R> {
    pub fn new(mut reader: R, algo: T, padding: X) -> Result<CbcReader<T, DecPadding<X>, R>> {
        let bs = algo.block_size();
        let mut iv = vec![0u8; bs];
        reader.read_exact(&mut iv)?;

        AesReader::new(reader, CbcDecryptor::new(algo, padding, iv), bs).map(|a| Self(a))
    }
}
use std::ops::{Deref, DerefMut};
impl<T: BlockDecryptor, X: PaddingProcessor, R: Read> Deref for EcbReader<T, X, R> {
    type Target = AesReader<EcbDecryptor<T, X>, R>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T: BlockDecryptor, X: PaddingProcessor, R: Read> DerefMut for EcbReader<T, X, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<T: BlockDecryptor, X: PaddingProcessor, R: Read> Deref for CbcReader<T, X, R> {
    type Target = AesReader<CbcDecryptor<T, X>, R>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T: BlockDecryptor, X: PaddingProcessor, R: Read> DerefMut for CbcReader<T, X, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
