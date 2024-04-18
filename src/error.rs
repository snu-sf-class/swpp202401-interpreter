use crate::{common::BitWidth, register::SwppRegisterName};

pub type SwppResult<T> = Result<T, SwppError>;
pub type SwppRawResult<T> = Result<T, SwppErrorKind>;

/// 발생하는 에러의 종류
/// associated value는 desc함수 참조
#[derive(Debug, Clone)]
pub enum SwppErrorKind {
    /// 메인 함수가 없음
    NoMainFn,
    /// 선언되지 않은 함수를 실행
    UnknownFnName(String),
    /// 선언되지 않은 블록으로 접근
    UnknownBlockName(String),
    /// 블록이 올바르게 종료되지 않음
    IllFormedBlock(String),
    /// 잘못된 레지스터이름
    WrongRegisterName(SwppRegisterName),
    /// 벡터 레지스터가 들어갈 자리에 아닌 레지스터가 들어감
    ExpectVecReg(SwppRegisterName),
    /// 비-벡터 레지스터가 들어갈 자리에 벡터 레지스터가 들어감
    ExpectNonVecReg(SwppRegisterName),
    /// Arg 레지스터에 직접 값을 대입하려고 시도함
    ArgRegAssign(SwppRegisterName),
    /// Condition register에 잘못된 값 사용
    InvalidCondVal(u64),
    /// Function 실행중 오류
    /// 함수이름 xx가 어떤 에러 statement와 함께 종료되었는지 설명
    FunctionCallCrash(String, String),
    /// 잘못된 인자의 갯수로 호출
    WrongArgNum(String, u64, u64),
    /// 레지스터에 없는 값(리턴 없는 함수의 반환값등) 을 저장하려 시도
    AssignNoValue(String),
    /// 메인함수의 재귀호출
    RecursiveMainCall,
    /// 허용되지않는 재귀호출
    InvalidRecursiveCall(String, String),
    /// Assert 실패
    AssertionFailed(u64, u64),
    /// 힙 할당 사이즈가 잘못됨
    InvalidHeapAllocSize(u64),
    /// 힙 메모리 부족
    NOMEMHEAP,
    /// 잘못된 메모리 주소
    InvalidAddr(u64),
    /// 잘못된 alignment
    InvalidAlignment(u64, u64),
    /// Vector inst에 대한 잘못된 bitwidth
    InvalidBitwidth(BitWidth),
    /// Vector Manipulation 연산에 대한 잘못된 인덱스
    InvalidIndex(u64),
    /// read write fails
    IOFails,
    /// 잘못된 입력
    InvalidIOValue(String),
    SubtractOverFlow,
}

impl SwppErrorKind {
    pub fn desc(&self) -> String {
        match self {
            SwppErrorKind::NoMainFn => String::from("Main Function does not exists"),
            SwppErrorKind::UnknownFnName(fname) => format!("Function {} isn't declared", &fname),
            SwppErrorKind::UnknownBlockName(bname) => format!("Block {} isn't declared", &bname),
            SwppErrorKind::IllFormedBlock(bname) => format!("Block {} is not well formed", &bname),
            SwppErrorKind::WrongRegisterName(rname) => {
                format!("Register {} doesn't exist in system", rname.to_string())
            }
            SwppErrorKind::ExpectVecReg(rname) => {
                format!("Expected Vector Register but find {}", rname.to_string())
            }
            SwppErrorKind::ArgRegAssign(rname) => format!(
                "You cannot assign the value directly to the argument register {}",
                rname.to_string()
            ),
            SwppErrorKind::ExpectNonVecReg(rname) => format!(
                "Expected non-Vector Register but find {}",
                rname.to_string()
            ),
            SwppErrorKind::InvalidCondVal(val) => {
                format!("Condition register must have 0 or 1 but you use {}", val)
            }
            SwppErrorKind::FunctionCallCrash(fname, error_stmt) => format!(
                "While running {fname}, following error occurs \n-------------------------------------------------\n {error_stmt} \n-------------------------------------------------\n"
            ),
            SwppErrorKind::WrongArgNum(fname, right, wrong) => {
                format!("Function {fname} takes {right} arguments but you give {wrong}")
            }
            SwppErrorKind::AssignNoValue(fname) => format!(
                "{fname} returns nothing."
            ),
            SwppErrorKind::RecursiveMainCall => {
                String::from("Main function cannot be recursively called")
            }
            SwppErrorKind::InvalidRecursiveCall(fname, context) => {
                format!("You cannot recursively call {fname} in the function {context}")
            }
            SwppErrorKind::AssertionFailed(rhs, lhs) => format!(
                "Assertion Failed. Right side has value {rhs:?} while left side has value {lhs:?}"
            ),
            SwppErrorKind::InvalidHeapAllocSize(size) => {
                format!("Size for heap allocation {size} should be non-zero and multiple of 8")
            }
            SwppErrorKind::NOMEMHEAP => {
                "Heap Memory is actually limited with size of 2^64 bytes.".to_string()
            }
            SwppErrorKind::InvalidAddr(addr) => {
                format!("Error occurs while trying to access adress {addr}")
            }
            SwppErrorKind::InvalidAlignment(addr, size) => {
                format!("{addr} should be multiple of {size}")
            }
            SwppErrorKind::InvalidBitwidth(bw) => {
                let bitwidth: u64 = bw.clone().into();
                format!("Bitwidth {bitwidth} is not allowed for vector instruction")
            }
            SwppErrorKind::InvalidIndex(idx) => {
                format!("Wrong index {idx} to access vector in given bitwidth")
            }
            SwppErrorKind::IOFails =>{
                String::from("fail to read or write to stdstream")
            }
            SwppErrorKind::InvalidIOValue(input) => {
                format!("Read Invalid value {input}")
            }
            SwppErrorKind::SubtractOverFlow => {
                "Overflow occurs while subtract".to_string()
            },
        }
    }
}

#[derive(Debug)]
pub struct SwppError {
    /// 발생한 에러의 종류
    kind: SwppErrorKind,
    /// 에러의 발생 위치
    loc: u64,
}

impl SwppError {
    pub fn new(kind: SwppErrorKind, loc: u64) -> Self {
        Self { kind, loc }
    }

    pub fn get_kind(&self) -> SwppErrorKind {
        self.kind.clone()
    }
}

impl ToString for SwppError {
    fn to_string(&self) -> String {
        format!("{} : line {}", self.kind.desc(), self.loc)
    }
}
