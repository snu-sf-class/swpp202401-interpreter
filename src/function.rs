use std::collections::HashMap;

use crate::{
    error::{SwppError, SwppResult},
    logger::SwppLogger,
    program::{BlockResult, SwppBlock, SwppState},
    register::SwppRegisterSet,
};

/// Function is just set of named block
#[derive(Debug, Clone)]
pub struct SwppFunction {
    /// 함수의 이름
    fname: String,
    /// 인자의 갯수
    nargs: u64,
    /// 시작점
    entry: SwppBlock,
    /// 전체 블록
    block_map: HashMap<String, SwppBlock>,
    /// 현재 함수의 레지스터 상태
    local_register: SwppRegisterSet,
}

impl SwppFunction {
    pub fn new(fname: String, nargs: u64, blocks: Vec<SwppBlock>) -> Self {
        let entry = blocks.first().expect("Empty Function not allowed").clone();
        let block_map = blocks
            .into_iter()
            .map(|b| (b.get_block_name(), b))
            .collect();
        Self {
            fname,
            nargs,
            entry,
            block_map,
            local_register: SwppRegisterSet::default(),
        }
    }

    pub fn run(
        &mut self,
        state: &mut SwppState,
        prev_reg: &SwppRegisterSet,
        args: Vec<u64>,
        logger: &mut SwppLogger,
    ) -> SwppResult<Option<u64>> {
        logger.enter_fn();
        self.local_register = prev_reg.clone();
        self.local_register.set_arg_register(&args);

        // if self.fname == "write"{
        //     println!("{:?}",self.local_register);
        // }

        let mut next = self.entry.run(state, &mut self.local_register, logger)?;
        loop {
            match next {
                BlockResult::NextBlock(ref block_name, line_num) => {
                    let next_block = self.block_map.get(block_name).ok_or(SwppError::new(
                        crate::error::SwppErrorKind::UnknownBlockName(block_name.to_owned()),
                        line_num,
                    ));
                    next = next_block?.run(state, &mut self.local_register, logger)?;
                }
                BlockResult::Return(val) => {
                    logger.exit_fn();
                    return Ok(val);
                }
            }
        }
    }

    pub fn nargs(&self) -> u64 {
        self.nargs
    }

    pub fn fname(&self) -> String {
        self.fname.clone()
    }
}
