use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{digit0, space0},
    sequence::terminated,
    IResult,
};

use crate::register::SwppRegisterName;

use super::common::INVALID_REGISTER_IDX;

pub fn reg_parser(input: &str) -> IResult<&str, SwppRegisterName> {
    alt((numbered_reg_parser, sp_reg_parser))(input)
}

fn sp_reg_parser(input: &str) -> IResult<&str, SwppRegisterName> {
    let (rem, _) = terminated(tag("sp"), space0)(input)?;
    Ok((rem, SwppRegisterName::StackPointer))
}

fn numbered_reg_parser(input: &str) -> IResult<&str, SwppRegisterName> {
    let (rem, reg_type) = alt((tag("r"), tag("v"), tag("arg")))(input)?;
    let (rem, idx) = digit0(rem)?;

    let register_idx = idx
        .parse()
        .map_err(|_|
            nom::Err::Error(nom::error::Error::new(INVALID_REGISTER_IDX, nom::error::ErrorKind::Fail))
        )?;
    match reg_type {
        "r" => {
            if register_idx > 32 {
                return Err(nom::Err::Error(nom::error::Error::new(INVALID_REGISTER_IDX, nom::error::ErrorKind::Fail)));
            } else {
                Ok((rem, SwppRegisterName::Gen(register_idx)))
            }
        }
        "v" => {
            if register_idx > 16 {
                return Err(nom::Err::Error(nom::error::Error::new(INVALID_REGISTER_IDX, nom::error::ErrorKind::Fail)));
            } else {
                Ok((rem, SwppRegisterName::Vec(register_idx)))
            }
        }
        "arg" => {
            if register_idx > 16 {
                return Err(nom::Err::Error(nom::error::Error::new(INVALID_REGISTER_IDX, nom::error::ErrorKind::Fail)));
            } else {
                Ok((rem, SwppRegisterName::Argument(register_idx)))
            }
        }
        _ => unreachable!(),
    }
}

// #[test]
// fn arg_parser_test(){
//     assert_eq!(ParserArg::Reg(SwppRegisterName::Gen(27)),parse_arg("r27").unwrap().1.unwrap());
//     assert_eq!(ParserArg::Reg(SwppRegisterName::StackPointer),parse_arg("sp").unwrap().1.unwrap());
//     assert_eq!(ParserArg::Reg(SwppRegisterName::Argument(13)),parse_arg("arg13").unwrap().1.unwrap());
//     assert_eq!(ParserArg::Reg(SwppRegisterName::Vec(15)),parse_arg("v15").unwrap().1.unwrap());
//     assert_eq!(ParserArg::Fname("sp55".to_string()),parse_arg("sp55").unwrap().1.unwrap());
//     assert_eq!(ParserArg::Fname("sp ".to_string()),parse_arg("sp ").unwrap().1.unwrap());

//     parse_arg("v17").unwrap().1.unwrap_err();
//     parse_arg("r33").unwrap().1.unwrap_err();
//     parse_arg("arg66").unwrap().1.unwrap_err();

// }
