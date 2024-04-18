pub mod block;
pub mod common;
pub mod function;
pub mod inst;
pub mod reg;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while},
    character::complete::{digit1, multispace0, newline, space0},
    multi::many0,
    sequence::terminated,
    IResult,
};

use crate::program::SwppState;

use self::{common::ParserResult, function::function_parser};

fn line_num_parser(input: &str) -> IResult<&str, u64> {
    let (rem, _) = multispace0(input)?;
    let (rem, num_str) = terminated(digit1, tag(":"))(rem)?;
    let (rem, _) = space0(rem)?;
    Ok((rem, num_str.parse().unwrap()))
}

fn comment_parser(input: &str) -> IResult<&str, ParserResult> {
    let (rem, _) = line_num_parser(input)?;
    let (rem, _) = space0(rem)?;
    let (rem, _) = tag(";")(rem)?;
    let (rem, _) = take_while(|c| c != '\n')(rem)?;
    Ok((rem, ParserResult::Comment))
}

fn empty_parser(input: &str) -> IResult<&str, ParserResult> {
    let (rem, _) = line_num_parser(input)?;
    let (rem, _) = newline(rem)?;

    Ok((rem, ParserResult::Comment))
}

fn comment_empty_parser(input: &str) -> IResult<&str, ParserResult> {
    let (rem, _) = alt((comment_parser, empty_parser))(input)?;
    let (rem, _) = multispace0(rem)?;
    Ok((rem, ParserResult::Comment))
}

#[test]
fn commnet_empty_parser_test() {
    println!(
        "{:?}",
        comment_empty_parser(
            "23:
    24:start main 0:
    25:.entry:
    26:r1 = call read
    27:r1 = call countSetBits r1
    28:call write r1
    29:r15 = const 0
    30:ret r15
    31:end main
    32:"
        )
    );
}

pub fn preprocess(prog: &str) -> String {
    prog.split("\n")
        .enumerate()
        .map(|(line_num, line)| format!("{}:{line}\n", line_num + 1))
        .fold(String::new(), |mut a, b| {
            a.push_str(&b);
            a
        })
}

pub fn total_program_parser(prog: &str) -> SwppState {
    let prog = preprocess(prog);

    let function_comm_parser = alt((comment_empty_parser, function_parser));

    let (_, f_vec) = many0(function_comm_parser)(&prog).unwrap();

    let f_vec = f_vec
        .into_iter()
        .filter_map(|pres| match pres {
            ParserResult::Fn(f) => Some(f),
            ParserResult::Comment => None,
            _ => unreachable!(),
        })
        .collect();

    SwppState::new(f_vec)
}
