use std::collections::HashMap;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::{
        complete::{alpha1, digit1, space0},
        is_newline,
    },
    multi::{many0, many_till},
    sequence::{preceded, tuple},
    IResult, Parser,
};

use crate::{
    common::{AccessSize, Arg, BitWidth, ICMP},
    inst::{
        InstAdd, InstAssertion, InstBitwiseAnd, InstBitwiseOr, InstBitwiseXor, InstComparison,
        InstCondBr, InstConst, InstDecrement, InstFunctionCall, InstHeapAllocation, InstHeapFree,
        InstIncrement, InstLoad, InstMultiplication, InstParallelSignedVectorDivision,
        InstParallelSignedVectorRemainder, InstParallelUnsignedVectorDivision,
        InstParallelUnsignedVectorRemainder, InstParallelVectorAdd, InstParallelVectorAnd,
        InstParallelVectorComparison, InstParallelVectorMultiplication, InstParallelVectorOr,
        InstParallelVectorSub, InstParallelVectorTernary, InstParallelVectorXor, InstRecursiveCall,
        InstRet, InstShiftLeft, InstShiftRightArithmetic, InstShiftRightLogical,
        InstSignedDivision, InstSignedRemainder, InstSignedVectorDivision,
        InstSignedVectorRemainder, InstStore, InstSub, InstSwitch, InstTernary, InstUncondBr,
        InstUnsignedDivision, InstUnsignedRemainder, InstUnsignedVectorDivision,
        InstUnsignedVectorRemainder, InstVectorAdd, InstVectorAnd, InstVectorBroadcast,
        InstVectorComparison, InstVectorDecrement, InstVectorExtract, InstVectorIncrement,
        InstVectorLeftShift, InstVectorLoad, InstVectorMultiplication, InstVectorOr,
        InstVectorRightShiftArithmetic, InstVectorRightShiftLogical, InstVectorStore,
        InstVectorSub, InstVectorTernary, InstVectorUpdate, InstVectorXor, SwppInst, SwppInstKind,
    },
    parser::{line_num_parser, reg::reg_parser},
};

use super::{
    block::bname_parser,
    common::{gen_nom_err, ParserResult, INVALID_BW, INVALID_CONST, INVALID_ICMP, INVALID_SIZE},
    function::fname_parser,
};

pub fn inst_parser(input: &str) -> IResult<&str, ParserResult> {
    let (rem, _) = space0(input)?;
    // println!("5:{:?}",rem);

    let (ret_val, inst) = take_while1(|c| !is_newline(c as u8))(rem)?;
    // println!("5:{:?}",ret_val);
    let control_flow_parser = alt((
        ret_parser,
        ubranch_parser,
        branch_parser,
        switch_parser,
        fcall_parser,
        fcall_assign_parser,
        rcall_parser,
        rcall_assign_parser,
        assertion_parser,
    ));

    let (_, inst) = alt((
        control_flow_parser,
        malloc_parser,
        free_parser,
        load_parser,
        store_parser,
        vload_parser,
        vstore_parser,
        binary_parser,
        unary_parser,
        icmp_parser,
        ternary_parser,
        move_parser,
        broadcast_parser,
        extract_parser,
        update_parser,
        vec_ternary_parser,
    ))(inst)?;

    Ok((ret_val, ParserResult::Inst(inst)))
}

fn ret_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("ret")(input)?;
    // println!("1: {:?}",rem);
    let (rem, _) = space0(rem)?;
    // println!("2: {:?}",rem);
    if rem.is_empty() {
        let inst = SwppInst::new(SwppInstKind::Ret(InstRet::new(None)), line_num.clone());
        Ok((rem, inst))
    } else {
        let (rem, reg) = reg_parser(rem)?;
        let inst = SwppInst::new(SwppInstKind::Ret(InstRet::new(Some(reg))), line_num.clone());
        Ok((rem, inst))
    }
}

fn ubranch_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("br")(input)?;
    let (rem, _) = space0(rem)?;
    let (rem, bname) = bname_parser(rem)?;
    let inst = SwppInst::new(
        SwppInstKind::UBranch(InstUncondBr::new(bname.to_owned())),
        line_num,
    );
    Ok((rem, inst))
}

fn branch_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("br")(input)?;
    let (rem, cond_reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, true_bname) = preceded(space0, bname_parser)(rem)?;
    let (rem, false_bname) = preceded(space0, bname_parser)(rem)?;
    let inst = SwppInst::new(
        SwppInstKind::Branch(InstCondBr::new(
            cond_reg,
            true_bname.to_string(),
            false_bname.to_owned(),
        )),
        line_num,
    );
    Ok((rem, inst))
}

fn switch_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("switch")(input)?;
    let (rem, cond_reg) = preceded(space0, reg_parser)(rem)?;

    let cond_parser = preceded(space0, digit1);
    let block_parser = preceded(space0, bname_parser);

    let case_parser = tuple((cond_parser, block_parser));
    let (rem, (jump_vec, default)) = many_till(case_parser, preceded(space0, bname_parser))(rem)?;

    let jump_vec = jump_vec
        .into_iter()
        .map(|(val, block)| match val.parse() {
            Ok(cst) => Ok((cst, block.to_owned())),
            Err(_) => Err(gen_nom_err(&INVALID_CONST)),
        })
        .collect::<Result<HashMap<u64, String>, _>>()?;

    let inst = InstSwitch::new(cond_reg, jump_vec, default.to_string());
    let inst = SwppInst::new(SwppInstKind::Switch(inst), line_num);
    Ok((rem, inst))
}

fn fcall_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("call")(input)?;
    let (rem, fname) = preceded(space0, fname_parser)(rem)?;
    let (rem, args) = many0(preceded(space0, reg_parser))(rem)?;

    let inst = InstFunctionCall::new(None, fname.to_owned(), args);
    let inst = SwppInst::new(SwppInstKind::FnCall(inst), line_num);
    Ok((rem, inst))
}

fn fcall_assign_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("call")(rem)?;
    let (rem, fname) = preceded(space0, fname_parser)(rem)?;
    let (rem, args) = many0(preceded(space0, reg_parser))(rem)?;

    let inst = InstFunctionCall::new(Some(target), fname.to_owned(), args);
    let inst = SwppInst::new(SwppInstKind::FnCall(inst), line_num);
    Ok((rem, inst))
}

fn rcall_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("rcall")(input)?;
    // let (rem, fname) = preceded(space0, fname_parser)(rem)?;
    let (rem, args) = many0(preceded(space0, reg_parser))(rem)?;

    let inst = InstRecursiveCall::new(None, args);
    let inst = SwppInst::new(SwppInstKind::RCall(inst), line_num);
    Ok((rem, inst))
}

fn rcall_assign_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("rcall")(rem)?;
    // let (rem, fname) = preceded(space0, fname_parser)(rem)?;
    let (rem, args) = many0(preceded(space0, reg_parser))(rem)?;

    let inst = InstRecursiveCall::new(Some(target), args);
    let inst = SwppInst::new(SwppInstKind::RCall(inst), line_num);
    Ok((rem, inst))
}

fn assertion_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("assert_eq")(input)?;
    let (rem, lhs) = preceded(space0, reg_parser)(rem)?;
    let rhs_reg_parser = reg_parser.map(|reg| Arg::Reg(reg));
    let rhs_cst_parser = digit1.map(|cst: &str| Arg::Const(cst.parse().unwrap()));

    let (rem, rhs) = preceded(space0, alt((rhs_reg_parser, rhs_cst_parser)))(rem)?;

    let inst = InstAssertion::new(lhs, rhs);
    let inst = SwppInst::new(SwppInstKind::Assert(inst), line_num);
    Ok((rem, inst))
}

fn malloc_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("malloc")(rem)?;
    let (rem, size_reg) = preceded(space0, reg_parser)(rem)?;

    let inst = InstHeapAllocation::new(target, size_reg);
    let inst = SwppInst::new(SwppInstKind::Malloc(inst), line_num);
    Ok((rem, inst))
}

fn free_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("free")(input)?;
    let (rem, addr_reg) = preceded(space0, reg_parser)(rem)?;

    let inst = InstHeapFree::new(addr_reg);
    let inst = SwppInst::new(SwppInstKind::Free(inst), line_num);
    Ok((rem, inst))
}

fn size_parser(input: &str) -> IResult<&str, Option<AccessSize>> {
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

fn load_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("load")(rem)?;
    let (rem, size) = preceded(space0, size_parser)(rem)?;
    let size = size.ok_or(gen_nom_err(&INVALID_SIZE))?;
    let (rem, addr_reg) = preceded(space0, reg_parser)(rem)?;

    let inst = InstLoad::new(target, addr_reg, size);
    let inst = SwppInst::new(SwppInstKind::Load(inst), line_num);
    Ok((rem, inst))
}

fn store_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("store")(input)?;
    let (rem, size) = preceded(space0, size_parser)(rem)?;
    let size = size.ok_or(gen_nom_err(&INVALID_SIZE))?;
    let (rem, val_reg) = preceded(space0, reg_parser)(rem)?;

    // println!("1:{:?}",val_reg);
    let (rem, addr_reg) = preceded(space0, reg_parser)(rem)?;

    // println!("2:{:?}",addr_reg);
    let inst = InstStore::new(val_reg, addr_reg, size);
    let inst = SwppInst::new(SwppInstKind::Store(inst), line_num);
    Ok((rem, inst))
}

fn vload_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("vload")(rem)?;
    let (rem, addr_reg) = preceded(space0, reg_parser)(rem)?;

    let inst = InstVectorLoad::new(target, addr_reg);
    let inst = SwppInst::new(SwppInstKind::VLoad(inst), line_num);
    Ok((rem, inst))
}

fn vstore_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, _) = tag("vstore")(input)?;
    let (rem, val_reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, addr_reg) = preceded(space0, reg_parser)(rem)?;

    let inst = InstVectorStore::new(val_reg, addr_reg);
    let inst = SwppInst::new(SwppInstKind::VStore(inst), line_num);
    Ok((rem, inst))
}

fn bitwidth_parser(input: &str) -> IResult<&str, Option<BitWidth>> {
    let (rem, bw) = preceded(space0, digit1)(input)?;
    let bw: Result<u64, _> = bw.parse();
    if bw.is_err() {
        return Ok((rem, None));
    }
    let bw = bw.unwrap();
    let bw = if !(bw == 1 || bw == 8 || bw == 16 || bw == 32 || bw == 64) {
        None
    } else {
        Some(BitWidth::from(bw))
    };

    Ok((rem, bw))
}

fn binary_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;

    let normal_parser = alt((
        tag("udiv"),
        tag("sdiv"),
        tag("urem"),
        tag("srem"),
        tag("mul"),
        tag("shl"),
        tag("lshr"),
        tag("ashr"),
        tag("and"),
        tag("or"),
        tag("xor"),
        tag("add"),
        tag("sub"),
    ));

    let vparser = alt((
        tag("vudiv"),
        tag("vsdiv"),
        tag("vurem"),
        tag("vsrem"),
        tag("vmul"),
        tag("vshl"),
        tag("vlshr"),
        tag("vashr"),
        tag("vand"),
        tag("vor"),
        tag("vxor"),
        tag("vadd"),
        tag("vsub"),
    ));

    let vpparser = alt((
        tag("vpudiv"),
        tag("vpsdiv"),
        tag("vpurem"),
        tag("vpsrem"),
        tag("vpmul"),
        tag("vpand"),
        tag("vpor"),
        tag("vpxor"),
        tag("vpadd"),
        tag("vpsub"),
    ));

    let (rem, op) = alt((normal_parser, vparser, vpparser))(rem)?;
    let (rem, lhs) = preceded(space0, reg_parser)(rem)?;
    let (rem, rhs) = preceded(space0, reg_parser)(rem)?;
    let (rem, bw) = preceded(space0, bitwidth_parser)(rem)?;
    let bw = bw.ok_or(gen_nom_err(&INVALID_BW))?;

    let inst = match op {
        "udiv" => {
            let inst = InstUnsignedDivision::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::UDiv(inst), line_num)
        }
        "sdiv" => {
            let inst = InstSignedDivision::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::SDiv(inst), line_num)
        }
        "urem" => {
            let inst = InstUnsignedRemainder::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::URem(inst), line_num)
        }
        "srem" => {
            let inst = InstSignedRemainder::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::SRem(inst), line_num)
        }
        "mul" => {
            let inst = InstMultiplication::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Mul(inst), line_num)
        }
        "shl" => {
            let inst = InstShiftLeft::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Shl(inst), line_num)
        }
        "lshr" => {
            let inst = InstShiftRightLogical::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Lshr(inst), line_num)
        }
        "ashr" => {
            let inst = InstShiftRightArithmetic::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Ashr(inst), line_num)
        }
        "and" => {
            let inst = InstBitwiseAnd::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::And(inst), line_num)
        }
        "or" => {
            let inst = InstBitwiseOr::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Or(inst), line_num)
        }
        "xor" => {
            let inst = InstBitwiseXor::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Xor(inst), line_num)
        }
        "add" => {
            let inst = InstAdd::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Add(inst), line_num)
        }
        "sub" => {
            let inst = InstSub::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Sub(inst), line_num)
        }
        "vudiv" => {
            let inst = InstUnsignedVectorDivision::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vudiv(inst), line_num)
        }
        "vsdiv" => {
            let inst = InstSignedVectorDivision::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vsdiv(inst), line_num)
        }
        "vurem" => {
            let inst = InstUnsignedVectorRemainder::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vurem(inst), line_num)
        }
        "vsrem" => {
            let inst = InstSignedVectorRemainder::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vsrem(inst), line_num)
        }
        "vmul" => {
            let inst = InstVectorMultiplication::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vmul(inst), line_num)
        }
        "vshl" => {
            let inst = InstVectorLeftShift::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vshl(inst), line_num)
        }
        "vlshr" => {
            let inst = InstVectorRightShiftLogical::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vlshr(inst), line_num)
        }
        "vashr" => {
            let inst = InstVectorRightShiftArithmetic::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vashr(inst), line_num)
        }
        "vand" => {
            let inst = InstVectorAnd::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vand(inst), line_num)
        }
        "vor" => {
            let inst = InstVectorOr::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vor(inst), line_num)
        }
        "vxor" => {
            let inst = InstVectorXor::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vxor(inst), line_num)
        }
        "vadd" => {
            let inst = InstVectorAdd::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vadd(inst), line_num)
        }
        "vsub" => {
            let inst = InstVectorSub::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vsub(inst), line_num)
        }
        "vpudiv" => {
            let inst = InstParallelUnsignedVectorDivision::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpudiv(inst), line_num)
        }
        "vpsdiv" => {
            let inst = InstParallelSignedVectorDivision::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpsdiv(inst), line_num)
        }
        "vpurem" => {
            let inst = InstParallelUnsignedVectorRemainder::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpurem(inst), line_num)
        }
        "vpsrem" => {
            let inst = InstParallelSignedVectorRemainder::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpsrem(inst), line_num)
        }
        "vpmul" => {
            let inst = InstParallelVectorMultiplication::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpmul(inst), line_num)
        }
        "vpand" => {
            let inst = InstParallelVectorAnd::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpand(inst), line_num)
        }
        "vpor" => {
            let inst = InstParallelVectorOr::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpor(inst), line_num)
        }
        "vpxor" => {
            let inst = InstParallelVectorXor::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpxor(inst), line_num)
        }
        "vpadd" => {
            let inst = InstParallelVectorAdd::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpadd(inst), line_num)
        }
        "vpsub" => {
            let inst = InstParallelVectorSub::new(lhs, rhs, target, bw);
            SwppInst::new(SwppInstKind::Vpsub(inst), line_num)
        }
        _ => unreachable!(),
    };

    Ok((rem, inst))
}

fn unary_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, op) = alt((tag("incr"), tag("decr"), tag("vincr"), tag("vdecr")))(rem)?;
    let (rem, reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, bw) = preceded(space0, bitwidth_parser)(rem)?;
    let bw = bw.ok_or(gen_nom_err(&INVALID_BW))?;

    let inst = match op {
        "incr" => {
            let inst = InstIncrement::new(reg, target, bw);
            SwppInst::new(SwppInstKind::Incr(inst), line_num)
        }
        "decr" => {
            let inst = InstDecrement::new(reg, target, bw);
            SwppInst::new(SwppInstKind::Decr(inst), line_num)
        }
        "vincr" => {
            let inst = InstVectorIncrement::new(reg, target, bw);
            SwppInst::new(SwppInstKind::Vincr(inst), line_num)
        }
        "vdecr" => {
            let inst = InstVectorDecrement::new(reg, target, bw);
            SwppInst::new(SwppInstKind::Vdecr(inst), line_num)
        }
        _ => unreachable!(),
    };
    Ok((rem, inst))
}

fn icmp_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, op) = alt((tag("icmp"), tag("vicmp"), tag("vpcimp")))(rem)?;
    let (rem, cond) = preceded(space0, alpha1)(rem)?;
    let cond = match cond {
        "eq" => ICMP::Eq,
        "ne" => ICMP::Ne,
        "ugt" => ICMP::Ugt,
        "uge" => ICMP::Uge,
        "ult" => ICMP::Ult,
        "ule" => ICMP::Ule,
        "sgt" => ICMP::Sgt,
        "sge" => ICMP::Sge,
        "slt" => ICMP::Slt,
        "sle" => ICMP::Sle,
        _ => panic!("{} : {}", INVALID_ICMP, line_num),
    };
    let (rem, reg1) = preceded(space0, reg_parser)(rem)?;
    let (rem, reg2) = preceded(space0, reg_parser)(rem)?;
    let (rem, bw) = preceded(space0, bitwidth_parser)(rem)?;

    let bw = bw.ok_or(gen_nom_err(INVALID_BW))?;

    let inst = match op {
        "icmp" => {
            let inst = InstComparison::new(reg1, reg2, cond, target, bw);
            SwppInst::new(SwppInstKind::Comp(inst), line_num)
        }
        "vicmp" => {
            let inst = InstVectorComparison::new(reg1, reg2, cond, target, bw);
            SwppInst::new(SwppInstKind::Vicmp(inst), line_num)
        }
        "vpicmp" => {
            let inst = InstParallelVectorComparison::new(reg1, reg2, cond, target, bw);
            SwppInst::new(SwppInstKind::Vpicmp(inst), line_num)
        }
        _ => unreachable!(),
    };
    Ok((rem, inst))
}

fn ternary_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;

    let (rem, _) = tag("select")(rem)?;

    let (rem, cond_reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, true_reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, false_reg) = preceded(space0, reg_parser)(rem)?;
    let inst = InstTernary::new(false_reg, true_reg, cond_reg, target);
    let inst = SwppInst::new(SwppInstKind::Select(inst), line_num);

    Ok((rem, inst))
}

fn vec_ternary_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;

    let (rem, op) = alt((tag("vselect"), tag("vpselect")))(rem)?;

    let (rem, cond_reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, first_reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, second_reg) = preceded(space0, reg_parser)(rem)?;

    let (rem, bw) = preceded(space0, bitwidth_parser)(rem)?;
    let bw = bw.ok_or(gen_nom_err(INVALID_BW))?;

    let inst = match op {
        "vselect" => {
            let inst = InstVectorTernary::new(first_reg, second_reg, cond_reg, target, bw);
            SwppInst::new(SwppInstKind::Vselect(inst), line_num)
        }
        "vpselect" => {
            let inst = InstParallelVectorTernary::new(first_reg, second_reg, cond_reg, target, bw);
            SwppInst::new(SwppInstKind::Vpselect(inst), line_num)
        }
        _ => unreachable!(),
    };

    Ok((rem, inst))
}

fn move_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("const")(rem)?;

    let (rem, cst) = preceded(space0, digit1)(rem)?;
    let cst = cst.parse().map_err(|_| gen_nom_err(INVALID_CONST))?;

    let inst = InstConst::new(target, cst);
    let inst = SwppInst::new(SwppInstKind::Const(inst), line_num);
    Ok((rem, inst))
}

fn broadcast_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("vbcast")(rem)?;

    let (rem, reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, bw) = preceded(space0, bitwidth_parser)(rem)?;
    let bw = bw.ok_or(gen_nom_err(INVALID_BW))?;

    let inst = InstVectorBroadcast::new(reg, target, bw);
    let inst = SwppInst::new(SwppInstKind::Vbcast(inst), line_num);
    Ok((rem, inst))
}
fn extract_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("vextct")(rem)?;

    let (rem, reg) = preceded(space0, reg_parser)(rem)?;

    let (rem, idx) = preceded(space0, reg_parser)(rem)?;

    let (rem, bw) = preceded(space0, bitwidth_parser)(rem)?;
    let bw = bw.ok_or(gen_nom_err(INVALID_BW))?;

    let inst = InstVectorExtract::new(reg, target, idx, bw);
    let inst = SwppInst::new(SwppInstKind::Vextct(inst), line_num);
    Ok((rem, inst))
}
fn update_parser(input: &str) -> IResult<&str, SwppInst> {
    let (input, line_num) = line_num_parser(input)?;
    let (rem, target) = reg_parser(input)?;
    let (rem, _) = tuple((space0, tag("="), space0))(rem)?;
    let (rem, _) = tag("vupdate")(rem)?;

    let (rem, vec_reg) = preceded(space0, reg_parser)(rem)?;
    let (rem, reg) = preceded(space0, reg_parser)(rem)?;

    let (rem, idx) = preceded(space0, reg_parser)(rem)?;

    let (rem, bw) = preceded(space0, bitwidth_parser)(rem)?;
    let bw = bw.ok_or(gen_nom_err(INVALID_BW))?;

    let inst = InstVectorUpdate::new(vec_reg, target, reg, idx, bw);
    let inst = SwppInst::new(SwppInstKind::Vupdate(inst), line_num);
    Ok((rem, inst))
}
#[test]
fn parse_inst_test() {
    let fff = "2:    r1 = malloc r1
    3:    r2 = call read
    4:    r3 = call read
    5:    r4 = const 4294967296
    6:    r1 = mul r3 r4 64
    7:    r5 = sdiv r1 r4 64
    8:    r1 = const 4";
    println!("{:?}", inst_parser(fff));
}
