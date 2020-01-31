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

type EcbReader<B, P, R> = AesReader<EcbDecryptor<B, DecPadding<P>>, R>;
type CbcReader<B, P, R> = AesReader<CbcDecryptor<B, DecPadding<P>>, R>;

impl<T: BlockDecryptor, X: PaddingProcessor, R: Read> EcbReader<T, X, R> {
    pub fn new_ecb(reader: R, algo: T, padding: X) -> Result<EcbReader<T, X, R>> {
        let bs = algo.block_size();
        AesReader::new(reader, EcbDecryptor::new(algo, padding), bs)
    }

    pub fn new_cbc(mut reader: R, algo: T, padding: X) -> Result<CbcReader<T, X, R>> {
        let bs = algo.block_size();
        let mut iv = vec![0u8; bs];
        reader.read_exact(&mut iv)?;

        AesReader::new(reader, CbcDecryptor::new(algo, padding, iv), bs)
    }
}
