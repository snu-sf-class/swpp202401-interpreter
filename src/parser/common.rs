use nom::{
    character::complete::{digit1, space0},
    sequence::preceded,
    IResult,
};

use crate::{
    common::AccessSize, function::SwppFunction, inst::SwppInst, program::SwppBlock,
    register::SwppRegisterName,
};

pub const INVALID_REGISTER_IDX: &str = "Parsing Error : Invalid Register Index";
pub const INVALID_CONST: &str = "Parsing Error : Invalid Constant";
pub const INVALID_SIZE: &str = "Parsing Error : Invalid Acess Size";
pub const INVALID_BW: &str = "Parsing Error : Invalid Bitwidth";
pub const INVALID_ICMP: &str = "Parsing Error : Invalid ICMP Condition";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParserArg {
    Reg(SwppRegisterName),
    Const(u64),
    Fname(String),
    BBname(String),
}

#[derive(Debug, Clone)]
pub enum ParserResult {
    Fn(SwppFunction),
    Comment,
    Block(SwppBlock),
    Inst(SwppInst),
}

pub fn size_parser(input: &str) -> IResult<&str, Option<AccessSize>> {
    let (rem, size) = preceded(space0, digit1)(input)?;
    let size: Result<u64, _> = size.parse();
    if size.is_err() {
        return Ok((rem, None));
    }
    let size = size.unwrap();
    let size = if !(size == 1 || size == 2 || size == 4 || size == 8) {
        None
    } else {
        Some(AccessSize::from(size))
    };

    Ok((rem, size))
}

#[inline]
pub fn gen_nom_err(error_str: &'static str) -> nom::Err<nom::error::Error<&'static str>> {
    nom::Err::Error(nom::error::Error::new(
        error_str,
        nom::error::ErrorKind::Fail,
    ))
}
