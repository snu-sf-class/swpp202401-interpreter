use nom::{
    branch::alt,
    bytes::complete::{tag, take_till, take_until, take_while1},
    character::{
        complete::{digit1, multispace0, space0},
        is_alphanumeric,
    },
    multi::many0,
    sequence::{terminated, tuple},
    IResult,
};

use crate::{
    function::SwppFunction,
    parser::{block::block_parser, comment_empty_parser, common::INVALID_CONST, line_num_parser},
};

use super::common::ParserResult;

pub fn fname_parser(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| is_alphanumeric(c as u8) || c == '_' || c == '-' || c == '.')(input)
}

pub fn function_parser(input: &str) -> IResult<&str, ParserResult> {
    let (rem, _) = line_num_parser(input)?;
    let (rem, _) = tuple((space0, tag("start"), space0))(rem)?;
    // println!("First take : {:?}", takes);
    // println!("First rem : {:?}", rem);
    let (rem, start_fname) = terminated(take_till(|c| c == ' '), space0)(rem)?;
    let (rem, nargs) = terminated(digit1, tuple((tag(":"), multispace0)))(rem)?;
    let nargs = nargs.parse().expect(INVALID_CONST);
    // println!("nargs : {:?}", nargs);
    let f_end = format!("end {start_fname}");
    let f_endd = f_end.as_str();
    let (rem, fbody) = take_until(f_endd)(rem)?;
    // println!("Body : {:?}", fbody);
    let block_comm_parser = alt((block_parser, comment_empty_parser));

    // println!("{fbody}");

    let (_, block_vec) = many0(block_comm_parser)(fbody)?;

    // println!("{block_vec:?}");

    let block_vec = block_vec
        .into_iter()
        .filter_map(|pres| match pres {
            ParserResult::Block(b) => Some(b),
            ParserResult::Comment => None,
            _ => unreachable!(),
        })
        .collect();

    let function = SwppFunction::new(start_fname.to_owned(), nargs, block_vec);

    let (rem, (_, _, end_fname)) = tuple((tag("end"), space0, tag(start_fname)))(rem)?;
    assert_eq!(start_fname, end_fname);

    Ok((rem, ParserResult::Fn(function)))
}
