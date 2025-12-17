pub use crate::error::{StructError, ValkyrieError};
pub use crate::vtype::Endianess;

/// Fournit pack/unpack suivant endianness et bitness.
#[derive(Debug, Clone, Copy)]
pub struct VCoreStructs {
    endian: Endianess,
    bit: u16,
}

impl VCoreStructs {
    pub fn new(endian: Endianess, bit: u16) -> Result<Self, StructError> {
        match bit {
            16 | 32 | 64 => Ok(Self { endian, bit }),
            _ => Err(StructError::UnsupportedBitness),
        }
    }

    pub fn endian(&self) -> Endianess {
        self.endian
    }

    pub fn bit(&self) -> u16 {
        self.bit
    }

    /// self.pack
    pub fn pack(&self, x: u64) -> Vec<u8> {
        match self.bit {
            64 => self.pack64(x),
            32 => self.pack32(x as u32),
            16 => self.pack16(x as u16),
            _ => unreachable!(),
        }
    }

    /// self.packs (signed)
    pub fn packs(&self, x: i64) -> Vec<u8> {
        match self.bit {
            64 => self.pack64s(x),
            32 => self.pack32s(x as i32),
            16 => self.pack16s(x as i16),
            _ => unreachable!(),
        }
    }

    /// self.unpack
    pub fn unpack(&self, buf: &[u8]) -> Result<u64, StructError> {
        Ok(match self.bit {
            64 => self.unpack64(buf)?,
            32 => self.unpack32(buf)? as u64,
            16 => self.unpack16(buf)? as u64,
            _ => unreachable!(),
        })
    }

    /// self.unpacks (signed)
    pub fn unpacks(&self, buf: &[u8]) -> Result<i64, StructError> {
        Ok(match self.bit {
            64 => self.unpack64s(buf)?,
            32 => self.unpack32s(buf)? as i64,
            16 => self.unpack16s(buf)? as i64,
            _ => unreachable!(),
        })
    }

    // pack 64 bit
    pub fn pack64(&self, x: u64) -> Vec<u8> {
        match self.endian {
            Endianess::LittleEndian => x.to_le_bytes().to_vec(),
            Endianess::BigEndian => x.to_be_bytes().to_vec(),
        }
    }

    // pack 64bit signed
    pub fn pack64s(&self, x: i64) -> Vec<u8> {
        match self.endian {
            Endianess::LittleEndian => x.to_le_bytes().to_vec(),
            Endianess::BigEndian => x.to_be_bytes().to_vec(),
        }
    }

    // unpack 64bit
    pub fn unpack64(&self, buf: &[u8]) -> Result<u64, StructError> {
        let b = take_exact(buf, 8)?;
        Ok(match self.endian {
            Endianess::LittleEndian => u64::from_le_bytes(b),
            Endianess::BigEndian => u64::from_be_bytes(b),
        })
    }

    // unpack 64bit signed
    pub fn unpack64s(&self, buf: &[u8]) -> Result<i64, StructError> {
        let b = take_exact(buf, 8)?;
        Ok(match self.endian {
            Endianess::LittleEndian => i64::from_le_bytes(b),
            Endianess::BigEndian => i64::from_be_bytes(b),
        })
    }

    // pack 32bit
    pub fn pack32(&self, x: u32) -> Vec<u8> {
        match self.endian {
            Endianess::LittleEndian => x.to_le_bytes().to_vec(),
            Endianess::BigEndian => x.to_be_bytes().to_vec(),
        }
    }

    // pack 32bit signed
    pub fn pack32s(&self, x: i32) -> Vec<u8> {
        match self.endian {
            Endianess::LittleEndian => x.to_le_bytes().to_vec(),
            Endianess::BigEndian => x.to_be_bytes().to_vec(),
        }
    }

    // unpack 32bit
    pub fn unpack32(&self, buf: &[u8]) -> Result<u32, StructError> {
        let b = take_exact(buf, 4)?;
        Ok(match self.endian {
            Endianess::LittleEndian => u32::from_le_bytes(b),
            Endianess::BigEndian => u32::from_be_bytes(b),
        })
    }

    // unpack 32bit signed
    pub fn unpack32s(&self, buf: &[u8]) -> Result<i32, StructError> {
        let b = take_exact(buf, 4)?;
        Ok(match self.endian {
            Endianess::LittleEndian => i32::from_le_bytes(b),
            Endianess::BigEndian => i32::from_be_bytes(b),
        })
    }

    // pack 16bit
    pub fn pack16(&self, x: u16) -> Vec<u8> {
        match self.endian {
            Endianess::LittleEndian => x.to_le_bytes().to_vec(),
            Endianess::BigEndian => x.to_be_bytes().to_vec(),
        }
    }

    // pack 16bit signed
    pub fn pack16s(&self, x: i16) -> Vec<u8> {
        match self.endian {
            Endianess::LittleEndian => x.to_le_bytes().to_vec(),
            Endianess::BigEndian => x.to_be_bytes().to_vec(),
        }
    }

    // unpack 16bit
    pub fn unpack16(&self, buf: &[u8]) -> Result<u16, StructError> {
        let b = take_exact(buf, 2)?;
        Ok(match self.endian {
            Endianess::LittleEndian => u16::from_le_bytes(b),
            Endianess::BigEndian => u16::from_be_bytes(b),
        })
    }

    // unpack 16bit signed
    pub fn unpack16s(&self, buf: &[u8]) -> Result<i16, StructError> {
        let b = take_exact(buf, 2)?;
        Ok(match self.endian {
            Endianess::LittleEndian => i16::from_le_bytes(b),
            Endianess::BigEndian => i16::from_be_bytes(b),
        })
    }

    // pack 8bit
    pub fn pack8(&self, x: u8) -> [u8; 1] {
        [x]
    }

    // pack 8bit signed
    pub fn pack8s(&self, x: i8) -> [u8; 1] {
        [x as u8]
    }

    // unpack 8bit
    pub fn unpack8(&self, buf: &[u8]) -> Result<u8, StructError> {
        if buf.is_empty() {
            return Err(StructError::BufferTooSmall {
                expected: 1,
                got: buf.len(),
            });
        }
        Ok(buf[0])
    }

    // unpack 8bit signed
    pub fn unpack8s(&self, buf: &[u8]) -> Result<i8, StructError> {
        if buf.is_empty() {
            return Err(StructError::BufferTooSmall {
                expected: 1,
                got: buf.len(),
            });
        }
        Ok(buf[0] as i8)
    }
}

/// Lit exactement N octets depuis `buf` (comme struct.unpack: il faut au moins N)
fn take_exact<const N: usize>(buf: &[u8], expected: usize) -> Result<[u8; N], StructError> {
    debug_assert_eq!(N, expected);
    if buf.len() < N {
        return Err(StructError::BufferTooSmall {
            expected: N,
            got: buf.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[..N]);
    Ok(out)
}
