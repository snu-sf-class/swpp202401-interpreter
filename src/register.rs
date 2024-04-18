use crate::{
    common::MEM_STACK_SIZE,
    error::{SwppErrorKind, SwppRawResult},
};

/// This struct represents the local state of register
#[derive(Debug, Clone)]
pub struct SwppRegisterSet {
    /// 33 64-bit general register
    general: [u64; 32],
    /// 16 vector register
    vec: [VecReg; 16],
    /// stack pointer
    sp: u64,
    /// argument register
    arg: [u64; 16],
}

impl Default for SwppRegisterSet {
    fn default() -> Self {
        Self {
            general: Default::default(),
            vec: Default::default(),
            sp: MEM_STACK_SIZE,
            arg: Default::default(),
        }
    }
}

impl SwppRegisterSet {
    pub fn read_register_word(&self, rname: &SwppRegisterName) -> SwppRawResult<u64> {
        match rname {
            SwppRegisterName::Gen(idx) => Ok(self.general[*idx - 1]),
            SwppRegisterName::Vec(_idx) => Err(SwppErrorKind::ExpectNonVecReg(rname.clone())),
            SwppRegisterName::StackPointer => Ok(self.sp),
            SwppRegisterName::Argument(idx) => Ok(self.arg[*idx - 1]),
        }
    }

    pub fn write_register_word(&mut self, rname: &SwppRegisterName, val: u64) -> SwppRawResult<()> {
        match rname {
            SwppRegisterName::Gen(idx) => self.general[*idx - 1] = val,
            SwppRegisterName::Vec(_) => return Err(SwppErrorKind::ExpectNonVecReg(rname.clone())),
            SwppRegisterName::StackPointer => self.sp = val,
            SwppRegisterName::Argument(idx) => self.arg[*idx - 1] = val,
        };
        Ok(())
    }

    pub fn set_arg_register(&mut self, args: &Vec<u64>) {
        assert!(args.len() <= 16);
        for (i, arg) in args.iter().enumerate() {
            self.arg[i] = *arg;
        }
    }

    pub fn read_register_vec(&self, rname: &SwppRegisterName) -> SwppRawResult<&VecReg> {
        match rname {
            SwppRegisterName::Vec(idx) => Ok(&self.vec[*idx - 1]),
            _ => Err(SwppErrorKind::ExpectVecReg(rname.clone())),
        }
    }

    pub fn get_register_vec_mut(&mut self, rname: &SwppRegisterName) -> SwppRawResult<&mut VecReg> {
        match rname {
            SwppRegisterName::Vec(idx) => Ok(&mut self.vec[*idx - 1]),
            _ => Err(SwppErrorKind::ExpectVecReg(rname.clone())),
        }
    }

    pub fn get_register_word_mut(&mut self, rname: &SwppRegisterName) -> SwppRawResult<&mut u64> {
        match rname {
            SwppRegisterName::Gen(idx) => Ok(&mut self.general[*idx - 1]),
            SwppRegisterName::Vec(_idx) => Err(SwppErrorKind::ExpectNonVecReg(rname.clone())),
            SwppRegisterName::StackPointer => Ok(&mut self.sp),
            SwppRegisterName::Argument(idx) => Ok(&mut self.arg[*idx - 1]),
        }
    }

    pub fn print_gen_register(&self) -> String {
        format!("r : {:?}", self.general)
    }
}

#[derive(Debug, Clone, Default)]
pub struct VecReg {
    inner: [u64; 4],
}

impl VecReg {
    pub fn set_u64(&mut self, idx: usize, val: u64) {
        self.inner[idx] = val;
    }

    pub fn get_u64(&self, idx: usize) -> u64 {
        self.inner[idx]
    }

    pub fn get_u32(&self, idx: usize) -> u32 {
        let inner_slice = self.inner.as_slice();
        let inner_slice_u32: &[u32] = unsafe { std::mem::transmute(inner_slice) };
        inner_slice_u32[idx]
    }

    pub fn set_u32(&mut self, idx: usize, val: u32) {
        let inner_slice = self.inner.as_mut_slice();
        let inner_slice_u32: &mut [u32] = unsafe { std::mem::transmute(inner_slice) };
        inner_slice_u32[idx] = val;
    }
}

/// 레지스터를 접근하기 위한 인덱스
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwppRegisterName {
    ///General (0~31)
    Gen(usize),
    /// Vector (0~15)
    Vec(usize),
    /// sp
    StackPointer,
    /// arg (0~15)
    Argument(usize),
}

impl ToString for SwppRegisterName {
    fn to_string(&self) -> String {
        match self {
            SwppRegisterName::Gen(idx) => format!("r{}", idx),
            SwppRegisterName::Vec(idx) => format!("v{}", idx),
            SwppRegisterName::StackPointer => String::from("sp"),
            SwppRegisterName::Argument(idx) => format!("arg{}", idx),
        }
    }
}

impl SwppRegisterName {
    pub fn is_arg(&self) -> bool {
        match self {
            SwppRegisterName::Argument(_) => true,
            _ => false,
        }
    }

    pub fn is_vec(&self) -> bool {
        match self {
            SwppRegisterName::Vec(_) => true,
            _ => false,
        }
    }
}
