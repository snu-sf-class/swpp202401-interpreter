use std::collections::HashMap;

use derive_name::VariantName;
use derive_new::new;
use text_io::read;

use crate::{
    common::{AccessSize, Arg, BitWidth, HEAP_OFFSET, ICMP, MEM_STACK_SIZE},
    error::{SwppError, SwppErrorKind, SwppRawResult, SwppResult},
    logger::SwppLogger,
    program::{BlockResult, SwppState},
    register::{SwppRegisterName, SwppRegisterSet},
};

/// General form of instruction
#[derive(Debug, Clone, new)]
pub struct SwppInst {
    kind: SwppInstKind,
    loc: u64,
}

impl SwppInst {
    pub fn run(
        &self,
        state: &mut SwppState,
        reg_set: &mut SwppRegisterSet,
        logger: &mut SwppLogger,
    ) -> SwppResult<Option<BlockResult>> {
        let inst_name = self.kind.variant_name();
        logger.log_verbose(&reg_set);
        match &self.kind {
            SwppInstKind::Ret(ret) => {
                state.add_cost(1);

                let ret_val = ret
                    .val
                    .clone()
                    .map(|rname| reg_set.read_register_word(&rname))
                    .transpose()
                    .map_err(|err| SwppError::new(err, self.loc))?;

                // let ret_val_str = ret_val
                //     .clone()
                //     .map(|val| val.to_string())
                //     .unwrap_or(String::new());

                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                Ok(Some(BlockResult::Return(ret_val)))
            }
            SwppInstKind::UBranch(br) => {
                state.add_cost(30);
                logger.log(
                    self.loc,
                    inst_name,
                    30,
                    state.get_cost(),
                    state.get_context(),
                );
                Ok(Some(BlockResult::NextBlock(br.target.clone(), self.loc)))
            }
            SwppInstKind::Branch(br) => {
                let (next_block, cost) = br
                    .run(state, reg_set)
                    .map_err(|err| SwppError::new(err, self.loc))?;
                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                Ok(Some(BlockResult::NextBlock(next_block, self.loc)))
            }
            SwppInstKind::Switch(sw) => {
                let next_block = sw
                    .run(state, reg_set)
                    .map_err(|err| SwppError::new(err, self.loc))?;
                state.add_cost(60);
                logger.log(
                    self.loc,
                    inst_name,
                    60,
                    state.get_cost(),
                    state.get_context(),
                );
                Ok(Some(BlockResult::NextBlock(next_block, self.loc)))
            }
            SwppInstKind::FnCall(fcall) => {
                state.add_cost(30);
                logger.log(
                    self.loc,
                    &format!("{}-{}", inst_name, fcall.fname),
                    30,
                    state.get_cost(),
                    state.get_context(),
                );
                fcall
                    .run(state, reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::RCall(rcall) => {
                state.add_cost(10);
                logger.log(
                    self.loc,
                    inst_name,
                    10,
                    state.get_cost(),
                    state.get_context(),
                );
                rcall
                    .run(state, reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Assert(assertion) => assertion
                .run(reg_set)
                .map(|_| None)
                .map_err(|err| SwppError::new(err, self.loc)),
            SwppInstKind::Malloc(malloc) => {
                state.add_cost(150);
                logger.log(
                    self.loc,
                    inst_name,
                    150,
                    state.get_cost(),
                    state.get_context(),
                );
                malloc
                    .run(state, reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Free(free) => {
                state.add_cost(150);
                logger.log(
                    self.loc,
                    inst_name,
                    150,
                    state.get_cost(),
                    state.get_context(),
                );
                free.run(state, reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Load(load) => {
                let cost = load
                    .run(state, reg_set, logger)
                    .map_err(|err| SwppError::new(err, self.loc))?;

                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                Ok(None)
            }
            SwppInstKind::Store(store) => {
                let cost = store
                    .run(state, reg_set, logger)
                    .map_err(|err| SwppError::new(err, self.loc))?;
                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                Ok(None)
            }
            SwppInstKind::VLoad(vload) => {
                let cost = vload
                    .run(state, reg_set)
                    .map_err(|err| SwppError::new(err, self.loc))?;
                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                Ok(None)
            }
            SwppInstKind::VStore(vstore) => {
                let cost = vstore
                    .run(state, reg_set)
                    .map_err(|err| SwppError::new(err, self.loc))?;
                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                Ok(None)
            }
            SwppInstKind::UDiv(udiv) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                udiv.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::SDiv(sdiv) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                sdiv.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::URem(urem) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                urem.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::SRem(srem) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                srem.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Mul(mul) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                mul.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Shl(shl) => {
                state.add_cost(4);

                logger.log(
                    self.loc,
                    inst_name,
                    4,
                    state.get_cost(),
                    state.get_context(),
                );
                shl.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Lshr(lshr) => {
                state.add_cost(4);
                logger.log(
                    self.loc,
                    inst_name,
                    4,
                    state.get_cost(),
                    state.get_context(),
                );
                lshr.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Ashr(ashr) => {
                state.add_cost(4);
                logger.log(
                    self.loc,
                    inst_name,
                    4,
                    state.get_cost(),
                    state.get_context(),
                );
                ashr.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::And(and) => {
                state.add_cost(4);
                logger.log(
                    self.loc,
                    inst_name,
                    4,
                    state.get_cost(),
                    state.get_context(),
                );
                and.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Or(or) => {
                state.add_cost(4);
                logger.log(
                    self.loc,
                    inst_name,
                    4,
                    state.get_cost(),
                    state.get_context(),
                );
                or.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Xor(xor) => {
                state.add_cost(4);
                logger.log(
                    self.loc,
                    inst_name,
                    4,
                    state.get_cost(),
                    state.get_context(),
                );
                xor.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Add(add) => {
                state.add_cost(5);
                logger.log(
                    self.loc,
                    inst_name,
                    5,
                    state.get_cost(),
                    state.get_context(),
                );
                add.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Sub(sub) => {
                state.add_cost(5);
                logger.log(
                    self.loc,
                    inst_name,
                    5,
                    state.get_cost(),
                    state.get_context(),
                );
                sub.run(reg_set, logger)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Incr(incr) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                incr.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Decr(decr) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                decr.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Comp(comp) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                comp.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Select(select) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );
                select
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Const(cst) => {
                state.add_cost(1);
                logger.log(
                    self.loc,
                    inst_name,
                    1,
                    state.get_cost(),
                    state.get_context(),
                );

                cst.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vudiv(vudiv) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );

                vudiv
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vsdiv(vsdiv) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vsdiv
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vurem(vurem) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vurem
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vsrem(vsrem) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vsrem
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vmul(vmul) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vmul.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vshl(vshl) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vshl.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vlshr(vlshr) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vlshr
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vashr(vashr) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vashr
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vand(vand) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vand.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vor(vor) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vor.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vxor(vxor) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vxor.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vadd(vadd) => {
                state.add_cost(10);
                logger.log(
                    self.loc,
                    inst_name,
                    10,
                    state.get_cost(),
                    state.get_context(),
                );
                vadd.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vsub(vsub) => {
                state.add_cost(10);
                logger.log(
                    self.loc,
                    inst_name,
                    10,
                    state.get_cost(),
                    state.get_context(),
                );
                vsub.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vincr(vincr) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vincr
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vdecr(vdecr) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vdecr
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vicmp(vicmp) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vicmp
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vselect(vselect) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vselect
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpudiv(vpudiv) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vpudiv
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpsdiv(vpsidv) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vpsidv
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpurem(vpurem) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vpurem
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpsrem(vpsrem) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vpsrem
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpmul(vpmul) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vpmul
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpand(vpand) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vpand
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpor(vpor) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vpor.run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpxor(vpxor) => {
                state.add_cost(8);
                logger.log(
                    self.loc,
                    inst_name,
                    8,
                    state.get_cost(),
                    state.get_context(),
                );
                vpxor
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpadd(vpadd) => {
                state.add_cost(10);
                logger.log(
                    self.loc,
                    inst_name,
                    10,
                    state.get_cost(),
                    state.get_context(),
                );
                vpadd
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpsub(vpsub) => {
                state.add_cost(10);
                logger.log(
                    self.loc,
                    inst_name,
                    10,
                    state.get_cost(),
                    state.get_context(),
                );
                vpsub
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpicmp(vpicmp) => {
                state.add_cost(2);
                logger.log(
                    self.loc,
                    inst_name,
                    2,
                    state.get_cost(),
                    state.get_context(),
                );
                vpicmp
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vpselect(vpselect) => {
                let cost = 2;
                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                vpselect
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vbcast(vbcast) => {
                let cost = 4;
                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                vbcast
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vextct(vextct) => {
                let cost = 4;
                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                vextct
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Vupdate(vupdate) => {
                let cost = 4;
                state.add_cost(cost);
                logger.log(
                    self.loc,
                    inst_name,
                    cost,
                    state.get_cost(),
                    state.get_context(),
                );
                vupdate
                    .run(reg_set)
                    .map(|_| None)
                    .map_err(|err| SwppError::new(err, self.loc))
            }
            SwppInstKind::Read(read) => read
                .run()
                .map(|v| Some(BlockResult::Return(Some(v))))
                .map_err(|err| SwppError::new(err, self.loc)),
            SwppInstKind::Write(write) => write
                .run(reg_set)
                .map(|_| Some(BlockResult::Return(None)))
                .map_err(|err| SwppError::new(err, self.loc)),
        }
    }
}

#[derive(Debug, Clone, VariantName)]
pub enum SwppInstKind {
    Ret(InstRet),
    UBranch(InstUncondBr),
    Branch(InstCondBr),
    Switch(InstSwitch),
    FnCall(InstFunctionCall),
    RCall(InstRecursiveCall),
    Assert(InstAssertion),
    Malloc(InstHeapAllocation),
    Free(InstHeapFree),
    Load(InstLoad),
    Store(InstStore),
    VLoad(InstVectorLoad),
    VStore(InstVectorStore),
    UDiv(InstUnsignedDivision),
    SDiv(InstSignedDivision),
    URem(InstUnsignedRemainder),
    SRem(InstSignedRemainder),
    Mul(InstMultiplication),
    Shl(InstShiftLeft),
    Lshr(InstShiftRightLogical),
    Ashr(InstShiftRightArithmetic),
    And(InstBitwiseAnd),
    Or(InstBitwiseOr),
    Xor(InstBitwiseXor),
    Add(InstAdd),
    Sub(InstSub),
    Incr(InstIncrement),
    Decr(InstDecrement),
    Comp(InstComparison),
    Select(InstTernary),
    Const(InstConst),
    Vudiv(InstUnsignedVectorDivision),
    Vsdiv(InstSignedVectorDivision),
    Vurem(InstUnsignedVectorRemainder),
    Vsrem(InstSignedVectorRemainder),
    Vmul(InstVectorMultiplication),
    Vshl(InstVectorLeftShift),
    Vlshr(InstVectorRightShiftLogical),
    Vashr(InstVectorRightShiftArithmetic),
    Vand(InstVectorAnd),
    Vor(InstVectorOr),
    Vxor(InstVectorXor),
    Vadd(InstVectorAdd),
    Vsub(InstVectorSub),
    Vincr(InstVectorIncrement),
    Vdecr(InstVectorDecrement),
    Vicmp(InstVectorComparison),
    Vselect(InstVectorTernary),
    Vpudiv(InstParallelUnsignedVectorDivision),
    Vpsdiv(InstParallelSignedVectorDivision),
    Vpurem(InstParallelUnsignedVectorRemainder),
    Vpsrem(InstParallelSignedVectorRemainder),
    Vpmul(InstParallelVectorMultiplication),
    Vpand(InstParallelVectorAnd),
    Vpor(InstParallelVectorOr),
    Vpxor(InstParallelVectorXor),
    Vpadd(InstParallelVectorAdd),
    Vpsub(InstParallelVectorSub),
    Vpicmp(InstParallelVectorComparison),
    Vpselect(InstParallelVectorTernary),
    Vbcast(InstVectorBroadcast),
    Vextct(InstVectorExtract),
    Vupdate(InstVectorUpdate),
    Read(InstStdRead),
    Write(InstStdWrite),
}

/// Return Value
#[derive(Debug, Clone, new)]
pub struct InstRet {
    val: Option<SwppRegisterName>,
}

/// Unconditional Branch
#[derive(Debug, Clone, new)]
pub struct InstUncondBr {
    target: String,
}

#[derive(Debug, Clone, new)]
/// Conditional Branch
pub struct InstCondBr {
    cond_reg: SwppRegisterName,
    true_target: String,
    false_target: String,
}

impl InstCondBr {
    /// 현재 cond register를 읽고 그 값에 따라 다음으로 갈 블록 이름+코스트를 전달한다.
    pub fn run(
        &self,
        _state: &mut SwppState,
        reg_set: &mut SwppRegisterSet,
    ) -> SwppRawResult<(String, u64)> {
        let cond = reg_set.read_register_word(&self.cond_reg)?;
        match cond {
            0 => Ok((self.false_target.clone(), 30)),
            1 => Ok((self.true_target.clone(), 90)),
            _ => Err(SwppErrorKind::InvalidCondVal(cond)),
        }
    }
}

#[derive(Debug, Clone, new)]
/// Switch
pub struct InstSwitch {
    cond_reg: SwppRegisterName,
    /// 레지스터의 값을 적절한 블록으로 연결시켜주는 매핑
    jump_map: HashMap<u64, String>,
    default_block: String,
}

impl InstSwitch {
    pub fn run(
        &self,
        _state: &mut SwppState,
        reg_set: &mut SwppRegisterSet,
    ) -> SwppRawResult<String> {
        let cond = reg_set.read_register_word(&self.cond_reg)?;
        let next_block = self
            .jump_map
            .get(&cond)
            .unwrap_or(&self.default_block)
            .clone();
        Ok(next_block)
    }
}

#[derive(Debug, Clone, new)]
/// Function call
pub struct InstFunctionCall {
    target: Option<SwppRegisterName>,
    fname: String,
    args: Vec<SwppRegisterName>,
}

impl InstFunctionCall {
    pub fn run(
        &self,
        state: &mut SwppState,
        reg_set: &mut SwppRegisterSet,
        logger: &mut SwppLogger,
    ) -> SwppRawResult<()> {
        let mut function = state.get_fn_by_name(&self.fname)?.clone();

        // Argument 갯수 검사
        if self.args.len() as u64 != function.nargs() {
            return Err(SwppErrorKind::WrongArgNum(
                self.fname.clone(),
                function.nargs(),
                self.args.len() as u64,
            ));
        }

        let arg_set: Result<_, SwppErrorKind> = self
            .args
            .iter()
            .map(|x| reg_set.read_register_word(x))
            .collect();

        let caller_f = state.get_context().get_fname();
        state.change_f_context(&self.fname);

        let ret_val = function
            .run(state, reg_set, arg_set?, logger)
            .map_err(|err| SwppErrorKind::FunctionCallCrash(self.fname.clone(), err.to_string()))?;

        state.change_f_context(&caller_f);

        if let Some(reg) = &self.target {
            if let Some(val) = ret_val {
                reg_set.write_register_word(reg, val)
            } else {
                Err(SwppErrorKind::AssignNoValue(self.fname.clone()))
            }
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, new)]
/// Function call
pub struct InstRecursiveCall {
    target: Option<SwppRegisterName>,
    args: Vec<SwppRegisterName>,
}

impl InstRecursiveCall {
    pub fn run(
        &self,
        state: &mut SwppState,
        reg_set: &mut SwppRegisterSet,
        logger: &mut SwppLogger,
    ) -> SwppRawResult<()> {
        
        let context_fname = state.get_context().get_fname();
        let mut function = state.get_fn_by_name(&context_fname)?.clone();

        // Recursive Call 가능한지 검사
        // 1. 현재 실행중인 함수만 재귀호출 가능

        // Argument 갯수 검사
        if self.args.len() as u64 != function.nargs() {
            return Err(SwppErrorKind::WrongArgNum(
                context_fname.clone(),
                function.nargs(),
                self.args.len() as u64,
            ));
        }

        let arg_set: Result<_, SwppErrorKind> = self
            .args
            .iter()
            .map(|x| reg_set.read_register_word(x))
            .collect();

        let ret_val = function
            .run(state, reg_set, arg_set?, logger)
            .map_err(|err| SwppErrorKind::FunctionCallCrash(context_fname.clone(), err.to_string()))?;

        if let Some(reg) = &self.target {
            if let Some(val) = ret_val {
                reg_set.write_register_word(reg, val)
            } else {
                Err(SwppErrorKind::AssignNoValue(context_fname.clone()))
            }
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstAssertion {
    lhs: SwppRegisterName,
    rhs: Arg,
}

impl InstAssertion {
    pub fn run(&self, reg_set: &SwppRegisterSet) -> SwppRawResult<()> {
        let lhs_val = reg_set.read_register_word(&self.lhs)?;

        let rhs_val = match &self.rhs {
            Arg::Reg(reg) => reg_set.read_register_word(reg)?,
            Arg::Const(v) => *v,
        };
        if rhs_val == lhs_val {
            Ok(())
        } else {
            Err(SwppErrorKind::AssertionFailed(rhs_val, lhs_val))
        }
    }
}

/// Malloc
#[derive(Debug, Clone, new)]
pub struct InstHeapAllocation {
    target_reg: SwppRegisterName,
    size_reg: SwppRegisterName,
}

impl InstHeapAllocation {
    pub fn run(&self, state: &mut SwppState, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let size_u64 = reg_set.read_register_word(&self.size_reg)?;
        // Check size
        if size_u64 == 0 || size_u64 % 8 != 0 {
            return Err(SwppErrorKind::InvalidHeapAllocSize(size_u64));
        }

        let addr = state.malloc(size_u64)?;

        reg_set.write_register_word(&self.target_reg, addr)
    }
}

/// Free
#[derive(Debug, Clone, new)]
pub struct InstHeapFree {
    addr_reg: SwppRegisterName,
}

impl InstHeapFree {
    pub fn run(&self, state: &mut SwppState, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let addr = reg_set.read_register_word(&self.addr_reg)?;

        state.free(addr)
    }
}

/// Load
#[derive(Debug, Clone, new)]
pub struct InstLoad {
    target_reg: SwppRegisterName,
    addr_reg: SwppRegisterName,
    size: AccessSize,
}

impl InstLoad {
    pub fn run(
        &self,
        state: &mut SwppState,
        reg_set: &mut SwppRegisterSet,
        logger: &mut SwppLogger,
    ) -> SwppRawResult<u64> {
        if self.target_reg.is_arg() {
            return Err(SwppErrorKind::ArgRegAssign(self.target_reg.clone()));
        }
        let addr = reg_set.read_register_word(&self.addr_reg)?;

        let size: u64 = self.size.into();

        if addr % size != 0 {
            return Err(SwppErrorKind::InvalidAlignment(addr, size));
        }
        let (val, cost) = if addr <= MEM_STACK_SIZE {
            (state.read_from_stack(addr, self.size)?, 30)
        } else if addr >= HEAP_OFFSET {
            (state.read_from_heap(addr, self.size)?, 50)
        } else {
            return Err(SwppErrorKind::InvalidAddr(addr));
        };

        logger.log_mem_trace(format!(
            "Load the data {val} from Adress {addr} with size {size}\n"
        ));

        reg_set
            .write_register_word(&self.target_reg, val)
            .map(|_| cost)
    }
}

/// Store
#[derive(Debug, Clone, new)]
pub struct InstStore {
    val_reg: SwppRegisterName,
    addr_reg: SwppRegisterName,
    size: AccessSize,
}

impl InstStore {
    pub fn run(
        &self,
        state: &mut SwppState,
        reg_set: &mut SwppRegisterSet,
        logger: &mut SwppLogger,
    ) -> SwppRawResult<u64> {
        let val = reg_set.read_register_word(&self.val_reg)?;
        let addr = reg_set.read_register_word(&self.addr_reg)?;

        let size: u64 = self.size.into();

        if addr % size != 0 {
            return Err(SwppErrorKind::InvalidAlignment(addr, size));
        }

        let cost = if addr <= MEM_STACK_SIZE {
            state.write_to_stack(addr, val, self.size)?;
            30
        } else if addr >= HEAP_OFFSET {
            state.write_to_heap(addr, val, self.size)?;
            50
        } else {
            return Err(SwppErrorKind::InvalidAddr(addr));
        };

        logger.log_mem_trace(format!(
            "Store the data {val} into Adress {addr} with size {size}\n"
        ));

        Ok(cost)
    }
}

/// Vector Load
#[derive(Debug, Clone, new)]
pub struct InstVectorLoad {
    target_reg: SwppRegisterName,
    addr_reg: SwppRegisterName,
}

impl InstVectorLoad {
    pub fn run(&self, state: &mut SwppState, reg_set: &mut SwppRegisterSet) -> SwppRawResult<u64> {
        let addr = reg_set.read_register_word(&self.addr_reg)?;

        if addr % 8 != 0 {
            return Err(SwppErrorKind::InvalidAlignment(addr, 8));
        }

        let target = reg_set.get_register_vec_mut(&self.target_reg)?;

        let cost = if addr <= MEM_STACK_SIZE {
            for i in 0..4 {
                let block = state.read_from_stack(addr + i, AccessSize::Eight)?;
                target.set_u64(i as usize, block);
            }
            60
        } else if addr >= HEAP_OFFSET {
            for i in 0..4 {
                let block = state.read_from_heap(addr + i, AccessSize::Eight)?;
                target.set_u64(i as usize, block);
            }
            100
        } else {
            return Err(SwppErrorKind::InvalidAddr(addr));
        };
        Ok(cost)
    }
}

/// Vector Store
#[derive(Debug, Clone, new)]
pub struct InstVectorStore {
    vec_reg: SwppRegisterName,
    addr_reg: SwppRegisterName,
}

impl InstVectorStore {
    pub fn run(&self, state: &mut SwppState, reg_set: &mut SwppRegisterSet) -> SwppRawResult<u64> {
        let addr = reg_set.read_register_word(&self.addr_reg)?;

        if addr % 8 != 0 {
            return Err(SwppErrorKind::InvalidAlignment(addr, 8));
        }

        let vec_val = reg_set.read_register_vec(&self.vec_reg)?;

        let cost = if addr <= MEM_STACK_SIZE {
            for i in 0..4 {
                let vec_block = vec_val.get_u64(i);
                state.write_to_stack(addr, vec_block, AccessSize::Eight)?;
            }
            60
        } else if addr >= HEAP_OFFSET {
            for i in 0..4 {
                let vec_block = vec_val.get_u64(i);
                state.write_to_heap(addr, vec_block, AccessSize::Eight)?;
            }
            100
        } else {
            return Err(SwppErrorKind::InvalidAddr(addr));
        };
        Ok(cost)
    }
}

/// Unsigned Division
#[derive(Debug, Clone, new)]
pub struct InstUnsignedDivision {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstUnsignedDivision {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);
        let val = self.bw.read_u64(val1 / val2);

        logger.log_op(format!("{val1}/{val2} = {val}"));

        reg_set.write_register_word(&self.target_reg, val)
    }
}

/// Signed Division
#[derive(Debug, Clone, new)]
pub struct InstSignedDivision {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstSignedDivision {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val1: i64 = unsafe { std::mem::transmute(val1) };
        let val2: i64 = unsafe { std::mem::transmute(val2) };

        let val = self.bw.read_i64(val1 / val2);
        logger.log_op(format!("{val1}/{val2} = {val}"));

        let val = unsafe { std::mem::transmute(val) };

        reg_set.write_register_word(&self.target_reg, val)
    }
}

/// Unsigned Remainder
#[derive(Debug, Clone, new)]
pub struct InstUnsignedRemainder {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstUnsignedRemainder {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val = self.bw.read_u64(val1 % val2);

        logger.log_op(format!("{val1}%{val2} = {val}"));

        reg_set.write_register_word(&self.target_reg, val)
    }
}
/// Signed Remainder
#[derive(Debug, Clone, new)]
pub struct InstSignedRemainder {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstSignedRemainder {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val1: i64 = unsafe { std::mem::transmute(val1) };
        let val2: i64 = unsafe { std::mem::transmute(val2) };

        let val = self.bw.read_i64(val1 % val2);

        logger.log_op(format!("{val1}%{val2} = {val}"));

        let val = unsafe { std::mem::transmute(val) };

        reg_set.write_register_word(&self.target_reg, val)
    }
}

/// Multiplication
#[derive(Debug, Clone, new)]
pub struct InstMultiplication {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstMultiplication {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val = self.bw.read_u64(val1.wrapping_mul(val2));

        logger.log_op(format!("{val1}*{val2} = {val}"));

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstShiftLeft {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstShiftLeft {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val = self.bw.read_u64(val1 << val2);

        logger.log_op(format!("{val1}<<{val2} = {val}"));

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstShiftRightLogical {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstShiftRightLogical {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val = self.bw.read_u64(val1 >> val2);

        logger.log_op(format!("{val1}>>{val2} = {val}"));

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstShiftRightArithmetic {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstShiftRightArithmetic {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val1: i64 = unsafe { std::mem::transmute(val1) };

        let val = self.bw.read_i64(val1 >> val2);
        logger.log_op(format!("{val1}>>{val2} = {val}"));
        let val = unsafe { std::mem::transmute(val) };
        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstBitwiseAnd {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstBitwiseAnd {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        reg_set.write_register_word(&self.target_reg, self.bw.read_u64(val1 & val2))
    }
}

#[derive(Debug, Clone, new)]
pub struct InstBitwiseOr {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstBitwiseOr {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        reg_set.write_register_word(&self.target_reg, self.bw.read_u64(val1 | val2))
    }
}

#[derive(Debug, Clone, new)]
pub struct InstBitwiseXor {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstBitwiseXor {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        reg_set.write_register_word(&self.target_reg, self.bw.read_u64(val1 ^ val2))
    }
}

#[derive(Debug, Clone, new)]
pub struct InstAdd {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstAdd {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val = self.bw.read_u64(val1.wrapping_add(val2));
        logger.log_op(format!("{val1}+{val2} = {val}"));

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstSub {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstSub {
    pub fn run(&self, reg_set: &mut SwppRegisterSet, logger: &mut SwppLogger) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val = self.bw.read_u64(val1.wrapping_sub(val2));
        logger.log_op(format!("{val1}-{val2} = {val}"));

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstIncrement {
    reg1: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstIncrement {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);

        let val = self.bw.read_u64(val1.wrapping_add(1));

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstDecrement {
    reg1: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstDecrement {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);

        let val = self.bw.read_u64(val1.wrapping_sub(1));

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstComparison {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    cond: ICMP,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstComparison {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let val1 = self.bw.read_u64(reg_set.read_register_word(&self.reg1)?);
        let val2 = self.bw.read_u64(reg_set.read_register_word(&self.reg2)?);

        let val = self.cond.compare_u64(val1, val2) as u64;

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstTernary {
    false_reg: SwppRegisterName,
    true_reg: SwppRegisterName,
    cond_reg: SwppRegisterName,
    target_reg: SwppRegisterName,
    // bw : BitWidth,
}

impl InstTernary {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let cond = reg_set.read_register_word(&self.cond_reg)?;
        let val = match cond {
            0 => reg_set.read_register_word(&self.false_reg)?,
            1 => reg_set.read_register_word(&self.true_reg)?,
            _ => return Err(SwppErrorKind::InvalidCondVal(cond)),
        };

        reg_set.write_register_word(&self.target_reg, val)
    }
}

#[derive(Debug, Clone, new)]
pub struct InstConst {
    target_reg: SwppRegisterName,
    cst: u64,
}

impl InstConst {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        reg_set.write_register_word(&self.target_reg, self.cst)
    }
}

// --------------------------------------------Vector--------------------------------------------

#[derive(Debug, Clone, new)]
pub struct InstUnsignedVectorDivision {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstUnsignedVectorDivision {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    target_vec.set_u32(i, val1 / val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    target_vec.set_u64(i, val1 / val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstSignedVectorDivision {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstSignedVectorDivision {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    let val1_s: i32 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i32 = unsafe { std::mem::transmute(val2) };

                    let val = unsafe { std::mem::transmute(val1_s / val2_s) };

                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    let val1_s: i64 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i64 = unsafe { std::mem::transmute(val2) };

                    let val = unsafe { std::mem::transmute(val1_s / val2_s) };

                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstUnsignedVectorRemainder {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstUnsignedVectorRemainder {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    target_vec.set_u32(i, val1 % val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    target_vec.set_u64(i, val1 % val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstSignedVectorRemainder {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstSignedVectorRemainder {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    let val1_s: i32 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i32 = unsafe { std::mem::transmute(val2) };

                    let val = unsafe { std::mem::transmute(val1_s % val2_s) };

                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    let val1_s: i64 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i64 = unsafe { std::mem::transmute(val2) };

                    let val = unsafe { std::mem::transmute(val1_s % val2_s) };

                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorMultiplication {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorMultiplication {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    let val = val1.wrapping_mul(val2);
                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    let val = val1.wrapping_mul(val2);
                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorLeftShift {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorLeftShift {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    target_vec.set_u32(i, val1 << val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    target_vec.set_u64(i, val1 << val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorRightShiftLogical {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorRightShiftLogical {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    target_vec.set_u32(i, val1 >> val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    target_vec.set_u64(i, val1 >> val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorRightShiftArithmetic {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorRightShiftArithmetic {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    let val1_s: i32 = unsafe { std::mem::transmute(val1) };
                    let val = unsafe { std::mem::transmute(val1_s >> val2) };
                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    let val1_s: i64 = unsafe { std::mem::transmute(val1) };
                    let val = unsafe { std::mem::transmute(val1_s >> val2) };
                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorAnd {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorAnd {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    target_vec.set_u32(i, val1 & val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    target_vec.set_u64(i, val1 & val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorOr {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorOr {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    target_vec.set_u32(i, val1 | val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    target_vec.set_u64(i, val1 | val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorXor {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorXor {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    target_vec.set_u32(i, val1 ^ val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    target_vec.set_u64(i, val1 ^ val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorAdd {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorAdd {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    let val = val1.wrapping_add(val2);
                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    let val = val1.wrapping_add(val2);
                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorSub {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorSub {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    let val = val1.wrapping_sub(val2);
                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val2 = vec2.get_u64(i);
                    let val = val1.wrapping_sub(val2);
                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorIncrement {
    reg1: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorIncrement {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val = val1.wrapping_add(1);
                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val = val1.wrapping_add(1);
                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorDecrement {
    reg1: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorDecrement {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val = val1.wrapping_sub(1);
                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = vec1.get_u64(i);
                    let val = val1.wrapping_sub(1);
                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorComparison {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    cond: ICMP,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorComparison {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    let val1 = vec1.get_u32(i);
                    let val2 = vec2.get_u32(i);
                    let val = self.cond.compare_u32(val1, val2) as u32;
                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    let val1 = self.bw.read_u64(vec1.get_u64(i));
                    let val2 = self.bw.read_u64(vec2.get_u64(i));
                    let val = self.cond.compare_u64(val1, val2) as u64;
                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorTernary {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    cond_reg: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorTernary {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let cond = reg_set.read_register_vec(&self.cond_reg)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..8 {
                    match cond.get_u32(i) {
                        0 => {
                            target_vec.set_u32(i, vec2.get_u32(i));
                        }
                        1 => {
                            target_vec.set_u32(i, vec1.get_u32(i));
                        }
                        _ => {
                            return Err(SwppErrorKind::InvalidCondVal(cond.get_u32(i) as u64));
                        }
                    }
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..4 {
                    match cond.get_u64(i) {
                        0 => {
                            target_vec.set_u64(i, vec2.get_u64(i));
                        }
                        1 => {
                            target_vec.set_u64(i, vec1.get_u64(i));
                        }
                        _ => {
                            return Err(SwppErrorKind::InvalidCondVal(cond.get_u64(i)));
                        }
                    }
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelUnsignedVectorDivision {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelUnsignedVectorDivision {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    target_vec.set_u32(i, val1 / val2);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    target_vec.set_u32(i + 4, val1 / val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    target_vec.set_u64(i, val1 / val2);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    target_vec.set_u64(i + 2, val1 / val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelSignedVectorDivision {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelSignedVectorDivision {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);

                    let val1_s: i32 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i32 = unsafe { std::mem::transmute(val2) };
                    let val = unsafe { std::mem::transmute(val1_s / val2_s) };

                    target_vec.set_u32(i, val);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    let val1_s: i32 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i32 = unsafe { std::mem::transmute(val2) };
                    let val = unsafe { std::mem::transmute(val1_s / val2_s) };

                    target_vec.set_u32(i + 4, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);

                    let val1_s: i64 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i64 = unsafe { std::mem::transmute(val2) };
                    let val = unsafe { std::mem::transmute(val1_s / val2_s) };

                    target_vec.set_u64(i, val);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    let val1_s: i64 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i64 = unsafe { std::mem::transmute(val2) };
                    let val = unsafe { std::mem::transmute(val1_s / val2_s) };

                    target_vec.set_u64(i + 4, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelUnsignedVectorRemainder {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelUnsignedVectorRemainder {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    target_vec.set_u32(i, val1 % val2);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    target_vec.set_u32(i + 4, val1 % val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    target_vec.set_u64(i, val1 % val2);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    target_vec.set_u64(i + 2, val1 % val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelSignedVectorRemainder {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelSignedVectorRemainder {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);

                    let val1_s: i32 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i32 = unsafe { std::mem::transmute(val2) };
                    let val = unsafe { std::mem::transmute(val1_s % val2_s) };

                    target_vec.set_u32(i, val);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    let val1_s: i32 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i32 = unsafe { std::mem::transmute(val2) };
                    let val = unsafe { std::mem::transmute(val1_s % val2_s) };

                    target_vec.set_u32(i + 4, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);

                    let val1_s: i64 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i64 = unsafe { std::mem::transmute(val2) };
                    let val = unsafe { std::mem::transmute(val1_s % val2_s) };

                    target_vec.set_u64(i, val);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    let val1_s: i64 = unsafe { std::mem::transmute(val1) };
                    let val2_s: i64 = unsafe { std::mem::transmute(val2) };
                    let val = unsafe { std::mem::transmute(val1_s % val2_s) };

                    target_vec.set_u64(i + 4, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelVectorMultiplication {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelVectorMultiplication {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    let val = val1.wrapping_mul(val2);
                    target_vec.set_u32(i, val);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    let val = val1.wrapping_mul(val2);
                    target_vec.set_u32(i + 4, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    let val = val1.wrapping_mul(val2);
                    target_vec.set_u64(i, val);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    let val = val1.wrapping_mul(val2);
                    target_vec.set_u64(i + 2, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelVectorAnd {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelVectorAnd {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    target_vec.set_u32(i, val1 & val2);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    target_vec.set_u32(i + 4, val1 & val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    target_vec.set_u64(i, val1 & val2);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    target_vec.set_u64(i + 2, val1 & val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelVectorOr {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelVectorOr {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    target_vec.set_u32(i, val1 | val2);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    target_vec.set_u32(i + 4, val1 | val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    target_vec.set_u64(i, val1 | val2);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    target_vec.set_u64(i + 2, val1 | val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelVectorXor {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelVectorXor {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    target_vec.set_u32(i, val1 ^ val2);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    target_vec.set_u32(i + 4, val1 ^ val2);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    target_vec.set_u64(i, val1 ^ val2);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    target_vec.set_u64(i + 2, val1 ^ val2);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelVectorAdd {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelVectorAdd {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    let val = val1.wrapping_add(val2);
                    target_vec.set_u32(i, val);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    let val = val1.wrapping_add(val2);
                    target_vec.set_u32(i + 4, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    let val = val1.wrapping_add(val2);
                    target_vec.set_u64(i, val);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    let val = val1.wrapping_add(val2);
                    target_vec.set_u64(i + 2, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelVectorSub {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelVectorSub {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    let val = val1.wrapping_sub(val2);
                    target_vec.set_u32(i, val);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    let val = val1.wrapping_sub(val2);
                    target_vec.set_u32(i + 4, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    let val = val1.wrapping_sub(val2);
                    target_vec.set_u64(i, val);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    let val = val1.wrapping_sub(val2);
                    target_vec.set_u64(i + 2, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelVectorComparison {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    cond: ICMP,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelVectorComparison {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    let val1 = vec1.get_u32(2 * i);
                    let val2 = vec1.get_u32(2 * i + 1);
                    let val = self.cond.compare_u32(val1, val2) as u32;
                    target_vec.set_u32(i, val);

                    let val1 = vec2.get_u32(2 * i);
                    let val2 = vec2.get_u32(2 * i + 1);
                    let val = self.cond.compare_u32(val1, val2) as u32;
                    target_vec.set_u32(i + 4, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    let val1 = vec1.get_u64(2 * i);
                    let val2 = vec1.get_u64(2 * i + 1);
                    let val = self.cond.compare_u64(val1, val2) as u64;
                    target_vec.set_u64(i, val);

                    let val1 = vec2.get_u64(2 * i);
                    let val2 = vec2.get_u64(2 * i + 1);
                    let val = self.cond.compare_u64(val1, val2) as u64;
                    target_vec.set_u64(i + 2, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstParallelVectorTernary {
    reg1: SwppRegisterName,
    reg2: SwppRegisterName,
    cond_reg: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstParallelVectorTernary {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec1 = reg_set.read_register_vec(&self.reg1)?.clone();
        let vec2 = reg_set.read_register_vec(&self.reg2)?.clone();
        let cond = reg_set.read_register_vec(&self.cond_reg)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                for i in 0..4 {
                    match cond.get_u32(i) {
                        0 => {
                            target_vec.set_u32(i, vec1.get_u32(2 * i + 1));
                        }
                        1 => {
                            target_vec.set_u32(i, vec1.get_u32(2 * i));
                        }
                        _ => {
                            return Err(SwppErrorKind::InvalidCondVal(cond.get_u32(i) as u64));
                        }
                    }

                    match cond.get_u32(i + 4) {
                        0 => {
                            target_vec.set_u32(i + 4, vec2.get_u32(2 * i + 1));
                        }
                        1 => {
                            target_vec.set_u32(i + 4, vec2.get_u32(2 * i));
                        }
                        _ => {
                            return Err(SwppErrorKind::InvalidCondVal(cond.get_u32(i + 4) as u64));
                        }
                    }
                }
                Ok(())
            }
            BitWidth::Full => {
                for i in 0..2 {
                    match cond.get_u64(i) {
                        0 => {
                            target_vec.set_u64(i, vec1.get_u64(2 * i + 1));
                        }
                        1 => {
                            target_vec.set_u64(i, vec1.get_u64(2 * i));
                        }
                        _ => {
                            return Err(SwppErrorKind::InvalidCondVal(cond.get_u64(i) as u64));
                        }
                    }

                    match cond.get_u64(i + 2) {
                        0 => {
                            target_vec.set_u64(i + 2, vec2.get_u64(2 * i + 1));
                        }
                        1 => {
                            target_vec.set_u64(i + 2, vec2.get_u64(2 * i));
                        }
                        _ => {
                            return Err(SwppErrorKind::InvalidCondVal(cond.get_u64(i + 2) as u64));
                        }
                    }
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorBroadcast {
    val_reg: SwppRegisterName,
    target_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorBroadcast {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let val = reg_set.read_register_word(&self.val_reg)?.clone();
        let target_vec = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                let val = self.bw.read_u64(val) as u32;
                for i in 0..8 {
                    target_vec.set_u32(i, val);
                }
                Ok(())
            }
            BitWidth::Full => {
                let val = self.bw.read_u64(val);
                for i in 0..4 {
                    target_vec.set_u64(i, val);
                }
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorExtract {
    vec_reg: SwppRegisterName,
    target_reg: SwppRegisterName,
    idx_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorExtract {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let vec_val = reg_set.read_register_vec(&self.vec_reg)?.clone();
        let idx = reg_set.read_register_word(&self.idx_reg)?.clone();
        let target = reg_set.get_register_word_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                if idx > 8 {
                    return Err(SwppErrorKind::InvalidIndex(idx));
                }
                let val = vec_val.get_u32(idx as usize);
                *target = val as u64;
                Ok(())
            }
            BitWidth::Full => {
                if idx > 4 {
                    return Err(SwppErrorKind::InvalidIndex(idx));
                }
                let val = vec_val.get_u64(idx as usize);
                *target = val as u64;
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

#[derive(Debug, Clone, new)]
pub struct InstVectorUpdate {
    vec_reg: SwppRegisterName,
    target_reg: SwppRegisterName,
    val_reg: SwppRegisterName,
    idx_reg: SwppRegisterName,
    bw: BitWidth,
}

impl InstVectorUpdate {
    pub fn run(&self, reg_set: &mut SwppRegisterSet) -> SwppRawResult<()> {
        let mut vec_val = reg_set.read_register_vec(&self.vec_reg)?.clone();
        let val = reg_set.read_register_word(&self.val_reg)?.clone();
        let idx = reg_set.read_register_word(&self.idx_reg)?.clone();
        let target = reg_set.get_register_vec_mut(&self.target_reg)?;

        match self.bw {
            BitWidth::Quad => {
                if idx > 8 {
                    return Err(SwppErrorKind::InvalidIndex(idx));
                }
                let val = self.bw.read_u64(val) as u32;
                vec_val.set_u32(idx as usize, val);
                *target = vec_val;
                Ok(())
            }
            BitWidth::Full => {
                if idx > 4 {
                    return Err(SwppErrorKind::InvalidIndex(idx));
                }
                let val = self.bw.read_u64(val);
                vec_val.set_u64(idx as usize, val);
                *target = vec_val;
                Ok(())
            }
            _ => Err(SwppErrorKind::InvalidBitwidth(self.bw.clone())),
        }
    }
}

/// Only for predefiend function read
#[derive(Debug, Clone, new)]
pub struct InstStdRead {}

impl InstStdRead {
    pub fn run(&self) -> SwppRawResult<u64> {
        let val: u64 = read!();

        Ok(val)
    }
}

/// Only for predefiend function write
#[derive(Debug, Clone, new)]
pub struct InstStdWrite {}

impl InstStdWrite {
    pub fn run(&self, reg_set: &SwppRegisterSet) -> SwppRawResult<()> {
        let arg = SwppRegisterName::Argument(1);
        let write_val = reg_set.read_register_word(&arg)?;
        println!("{write_val}");
        Ok(())
    }
}
