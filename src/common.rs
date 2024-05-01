use crate::register::SwppRegisterName;
pub const MEM_STACK_SIZE: u64 = 102400;
pub const MAIN_NAME: &str = "main";
pub const INTERNAL_ERROR_MSG: &str =
    "Internal Logic Error. If students find this bug, please tell TAs.";
pub const HEAP_OFFSET: u64 = 204800;
pub const MAX_HEAP_SIZE: u64 = u64::MAX - HEAP_OFFSET;

#[derive(Debug, Clone, Copy)]
pub enum AccessSize {
    One,
    Two,
    Four,
    Eight,
}

impl From<u64> for AccessSize {
    fn from(value: u64) -> Self {
        match value {
            1 => Self::One,
            2 => Self::Two,
            4 => Self::Four,
            8 => Self::Eight,
            _ => unreachable!(),
        }
    }
}

impl From<AccessSize> for usize {
    fn from(value: AccessSize) -> Self {
        match value {
            AccessSize::One => 1,
            AccessSize::Two => 2,
            AccessSize::Four => 4,
            AccessSize::Eight => 8,
        }
    }
}
impl From<AccessSize> for u64 {
    fn from(value: AccessSize) -> Self {
        match value {
            AccessSize::One => 1,
            AccessSize::Two => 2,
            AccessSize::Four => 4,
            AccessSize::Eight => 8,
        }
    }
}

#[derive(Debug, Clone)]
pub enum BitWidth {
    Bit,   //1
    Byte,  //8
    Short, //16
    Quad,  //32
    Full,  //64
}

impl BitWidth {
    pub fn read_u64(&self, val: u64) -> u64 {
        let bit: u64 = self.clone().into();
        let shift = 64 - bit;
        if shift == 0 {
            val
        } else {
            let mask = (1u64 << bit) - 1;
            val & mask
        }
    }

    pub fn read_i64(&self, val: i64) -> i64 {
        let bit: u64 = self.clone().into();
        let shift = 64 - bit;
        if shift == 0 {
            val
        } else {
            let mask = (1i64 << bit) - 1;
            val & mask
        }
    }
}

impl From<u64> for BitWidth {
    fn from(value: u64) -> Self {
        match value {
            1 => Self::Bit,
            8 => Self::Byte,
            16 => Self::Short,
            32 => Self::Quad,
            64 => Self::Full,
            _ => panic!(),
        }
    }
}

impl From<BitWidth> for usize {
    fn from(value: BitWidth) -> Self {
        match value {
            BitWidth::Bit => 1,
            BitWidth::Byte => 8,
            BitWidth::Short => 16,
            BitWidth::Quad => 32,
            BitWidth::Full => 64,
        }
    }
}
impl From<BitWidth> for u64 {
    fn from(value: BitWidth) -> Self {
        match value {
            BitWidth::Bit => 1,
            BitWidth::Byte => 8,
            BitWidth::Short => 16,
            BitWidth::Quad => 32,
            BitWidth::Full => 64,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ICMP {
    Eq,
    Ne,
    Ugt,
    Uge,
    Ult,
    Ule,
    Sgt,
    Sge,
    Slt,
    Sle,
}

impl ICMP {
    pub fn compare_u64(&self, rhs: u64, lhs: u64) -> bool {
        let rhs_s: i64 = unsafe { std::mem::transmute(rhs) };
        let lhs_s: i64 = unsafe { std::mem::transmute(lhs) };

        match self {
            ICMP::Eq => rhs == lhs,
            ICMP::Ne => rhs != lhs,
            ICMP::Ugt => rhs > lhs,
            ICMP::Uge => rhs >= lhs,
            ICMP::Ult => rhs < lhs,
            ICMP::Ule => rhs <= lhs,
            ICMP::Sgt => rhs_s > lhs_s,
            ICMP::Sge => rhs_s >= lhs_s,
            ICMP::Slt => rhs_s < lhs_s,
            ICMP::Sle => rhs_s <= lhs_s,
        }
    }

    pub fn compare_u32(&self, rhs: u32, lhs: u32) -> bool {
        let rhs_s: i32 = unsafe { std::mem::transmute(rhs) };
        let lhs_s: i32 = unsafe { std::mem::transmute(lhs) };

        match self {
            ICMP::Eq => rhs == lhs,
            ICMP::Ne => rhs != lhs,
            ICMP::Ugt => rhs > lhs,
            ICMP::Uge => rhs >= lhs,
            ICMP::Ult => rhs < lhs,
            ICMP::Ule => rhs <= lhs,
            ICMP::Sgt => rhs_s > lhs_s,
            ICMP::Sge => rhs_s >= lhs_s,
            ICMP::Slt => rhs_s < lhs_s,
            ICMP::Sle => rhs_s <= lhs_s,
        }
    }
}

/// 상수일 수도 있는 포지션을 위한 값
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Reg(SwppRegisterName),
    Const(u64),
}