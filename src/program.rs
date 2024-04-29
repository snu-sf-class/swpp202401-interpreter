use std::collections::HashMap;

use crate::{
    common::{AccessSize, MAIN_NAME},
    error::{SwppError, SwppRawResult, SwppResult},
    function::SwppFunction,
    inst::{InstStdRead, InstStdWrite, SwppInst, SwppInstKind},
    logger::SwppLogger,
    memory::SwppMemory,
    register::SwppRegisterSet,
};

/// Result of Bl
pub enum BlockResult {
    /// 다음으로 점프할 블록이름과 에러처리를 위한 마지막 점프의 라인번호를 가져온다.
    NextBlock(String, u64),
    Return(Option<u64>),
}

#[derive(Debug, Clone)]
pub struct SwppBlock {
    block_name: String,
    inst_vec: Vec<SwppInst>,
    start_loc: u64,
}

impl SwppBlock {
    pub fn new(block_name: String, start_loc: u64) -> Self {
        Self {
            block_name,
            inst_vec: Vec::new(),
            start_loc,
        }
    }

    pub fn get_block_name(&self) -> String {
        self.block_name.clone()
    }

    pub fn add_inst(&mut self, inst: SwppInst) {
        self.inst_vec.push(inst);
    }

    /// run the block, and indicates the name of next block
    pub fn run(
        &self,
        state: &mut SwppState,
        reg: &mut SwppRegisterSet,
        logger: &mut SwppLogger,
    ) -> SwppResult<BlockResult> {
        state.change_b_context(&self.block_name);
        for inst in &self.inst_vec {
            if let Some(result) = inst.run(state, reg, logger)? {
                return Ok(result);
            }
        }
        Err(SwppError::new(
            crate::error::SwppErrorKind::IllFormedBlock(self.block_name.clone()),
            self.start_loc,
        ))
    }
}

/// Global State
pub struct SwppState {
    mem: SwppMemory,
    cur_cost: u64,
    /// 함수 이름으로 함수 구현체에 접근하게 해주는 해쉬맵
    functions: HashMap<String, SwppFunction>,
    /// 지금 실행되는 instruction이 무슨 함수, 블록 에 속해있는지 알려준다.
    cur_context: SwppContext,
}

impl SwppState {
    pub fn new(f_vec: Vec<SwppFunction>) -> Self {
        let mut functions: HashMap<String, SwppFunction> =
            f_vec.into_iter().map(|f| (f.fname(), f)).collect();

        let mut read_block = SwppBlock {
            block_name: "read".to_owned(),
            inst_vec: Vec::new(),
            start_loc: 0,
        };
        read_block.add_inst(SwppInst::new(SwppInstKind::Read(InstStdRead::new()), 0));

        let read_fun = SwppFunction::new("read".to_owned(), 0, vec![read_block]);

        let mut write_block = SwppBlock {
            block_name: "write".to_owned(),
            inst_vec: Vec::new(),
            start_loc: 0,
        };
        write_block.add_inst(SwppInst::new(SwppInstKind::Write(InstStdWrite::new()), 0));

        let write_fun = SwppFunction::new("write".to_owned(), 1, vec![write_block]);

        functions.insert("read".to_string(), read_fun);
        functions.insert("write".to_string(), write_fun);

        Self {
            mem: SwppMemory::new(),
            cur_cost: 0,
            functions,
            cur_context: SwppContext {
                fname: "main".to_owned(),
                bname: "entry".to_owned(),
            },
        }
    }

    pub fn get_fn_by_name(&mut self, fname: &str) -> SwppRawResult<&mut SwppFunction> {
        self.functions
            .get_mut(fname)
            .ok_or(crate::error::SwppErrorKind::UnknownFnName(fname.to_owned()))
    }
    pub fn add_cost(&mut self, cost: u64) {
        self.cur_cost += cost;
    }
    pub fn get_cost(&self) -> u64 {
        self.cur_cost
    }
    pub fn change_f_context(&mut self, fname: &str) {
        self.cur_context.fname = fname.to_owned();
    }
    pub fn change_b_context(&mut self, bname: &str) {
        self.cur_context.bname = bname.to_owned();
    }
    pub fn get_context(&self) -> &SwppContext {
        &self.cur_context
    }

    pub fn malloc(&mut self, size: u64) -> SwppRawResult<u64> {
        self.mem.malloc(size)
    }

    pub fn free(&mut self, addr: u64) -> SwppRawResult<()> {
        self.mem.free(addr)
    }

    pub fn read_from_stack(&self, addr: u64, size: AccessSize) -> SwppRawResult<u64> {
        self.mem.read_from_stack(addr, size)
    }

    pub fn read_from_heap(&self, addr: u64, size: AccessSize) -> SwppRawResult<u64> {
        self.mem.read_from_heap(addr, size)
    }

    pub fn write_to_stack(&mut self, addr: u64, val: u64, size: AccessSize) -> SwppRawResult<()> {
        self.mem.write_to_stack(addr, val, size)
    }
    pub fn write_to_heap(&mut self, addr: u64, val: u64, size: AccessSize) -> SwppRawResult<()> {
        self.mem.write_to_heap(addr, val, size)
    }
}

#[derive(Debug)]
pub struct SwppContext {
    /// 현재 실행되는 함수의 이름
    fname: String,
    /// 현재 실행되는 블록의 이름
    bname: String,
}

impl SwppContext {
    pub fn get_fname(&self) -> String {
        self.fname.to_owned()
    }
    pub fn get_bname(&self) -> String {
        self.bname.to_owned()
    }
}

/// Whole program parsed from given IR
pub struct SwppProgram {
    /// Global State of current Program
    state: SwppState,
    logger: SwppLogger,
}

impl<'a> SwppProgram {
    #[cfg(feature = "log")]
    pub fn new(
        state: SwppState,
        base_log_path: &str,
        mem_log_path: &str,
        op_log_path: &str,
    ) -> Self {
        Self {
            state,
            logger: SwppLogger::new(base_log_path, mem_log_path, op_log_path),
        }
    }

    #[cfg(not(feature = "log"))]
    pub fn new(state: SwppState) -> Self {
        Self {
            state,
            logger: SwppLogger::new(),
        }
    }

    pub fn total_cost(&self) -> u64 {
        self.state.cur_cost + self.state.mem.get_max_heap_size() * 1024
    }

    pub fn run(&mut self) -> SwppResult<()> {
        // println!("{:?}",self.state.functions);
        let mut main = self
            .state
            .functions
            .remove(MAIN_NAME)
            .ok_or(SwppError::new(crate::error::SwppErrorKind::NoMainFn, 0))?;
        main.run(
            &mut self.state,
            &SwppRegisterSet::default(),
            Vec::new(),
            &mut self.logger,
        )?;
        Ok(())
    }
}
