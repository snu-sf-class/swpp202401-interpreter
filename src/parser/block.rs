use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::{
        complete::{multispace0, newline},
        is_alphanumeric,
    },
    multi::many0,
    sequence::{preceded, terminated},
    IResult,
};

use crate::{
    parser::{comment_empty_parser, inst::inst_parser, line_num_parser},
    program::SwppBlock,
};

use super::common::ParserResult;

pub fn bname_parser(input: &str) -> IResult<&str, &str> {
    preceded(
        tag("."),
        take_while1(|c: char| is_alphanumeric(c as u8) || c == '_' || c == '-' || c == '.'),
    )(input)
}

#[test]
fn bname_test() {
    let bname = ".hello 5 .hi .def";
    println!("{:?}", bname_parser(bname))
}

pub fn block_parser(input: &str) -> IResult<&str, ParserResult> {
    let (rem, _) = multispace0(input)?;
    // println!("1: {:?}", rem);
    let (rem, line_num) = line_num_parser(rem)?;
    let (rem, bname) = terminated(bname_parser, tag(":"))(rem)?;
    // println!("2: {:?}", rem);
    let (rem, _) = multispace0(rem)?;
    // println!("3: {:?}", rem);

    let inst_comment_parser = alt((comment_empty_parser, inst_parser));

    let (rem, inst_vec) = many0(terminated(inst_comment_parser, newline))(rem)?;

    // println!("4: {:?}", rem);

    let mut block = SwppBlock::new(bname.to_owned(), line_num);

    for inst in inst_vec {
        match inst {
            ParserResult::Inst(i) => block.add_inst(i),
            ParserResult::Comment => continue,
            _ => unreachable!(),
        }
    }

    Ok((rem, ParserResult::Block(block)))
}
