// little-endian 8-byte value
#[derive(Debug, Clone,Copy, Default, PartialEq, Eq)]
pub struct SwppWord {
    inner: u64,
}

impl From<u64> for SwppWord {
    fn from(value: u64) -> Self {
        Self {
            inner: value.to_le(),
        }
    }
}

impl SwppWord {
    pub fn get_1_bytes(&self) -> Self {
        Self::from(self.inner >> 56)
    }

    pub fn get_2_bytes(&self) -> Self {
        Self::from(self.inner >> 48)
    }

    pub fn get_4_bytes(&self) -> Self {
        Self::from(self.inner >> 32)
    }

    pub fn get_8_bytes(&self) -> Self {
        *self
    }

    /// big-endian으로 바꿔서 반환
    pub fn into_val(self)->u64{
        self.inner.to_be()
    }
}

// little-endian 256-byte value
#[derive(Debug, Clone,Copy, Default)]
pub struct SwppLWord {
    inner: [u64;4],
}