use std::io::{Read, Write};

use crate::error::PqfileError;

pub const MAGIC: &[u8; 4] = b"PQFL";
pub const VERSION: u8 = 0x01;
pub const KEM_VARIANT: u16 = 768;
pub const KEM_CT_LEN: usize = 1088;
pub const NONCE_LEN: usize = 12;

pub struct PqfHeader {
    pub kem_ciphertext: [u8; KEM_CT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub original_size: u64,
}

impl PqfHeader {
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), std::io::Error> {
        w.write_all(MAGIC)?;
        w.write_all(&[VERSION])?;
        w.write_all(&KEM_VARIANT.to_le_bytes())?;
        w.write_all(&self.kem_ciphertext)?;
        w.write_all(&self.nonce)?;
        w.write_all(&self.original_size.to_le_bytes())?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, PqfileError> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(PqfileError::InvalidMagic);
        }

        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(PqfileError::UnsupportedVersion(version[0]));
        }

        let mut kem_variant_bytes = [0u8; 2];
        r.read_exact(&mut kem_variant_bytes)?;
        let kem_variant = u16::from_le_bytes(kem_variant_bytes);
        if kem_variant != KEM_VARIANT {
            return Err(PqfileError::UnsupportedKem(kem_variant));
        }

        let mut kem_ciphertext = [0u8; KEM_CT_LEN];
        r.read_exact(&mut kem_ciphertext)?;

        let mut nonce = [0u8; NONCE_LEN];
        r.read_exact(&mut nonce)?;

        let mut size_bytes = [0u8; 8];
        r.read_exact(&mut size_bytes)?;
        let original_size = u64::from_le_bytes(size_bytes);

        Ok(PqfHeader {
            kem_ciphertext,
            nonce,
            original_size,
        })
    }
}
