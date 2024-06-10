use std::{
    fs::File,
    io::{BufWriter, Write},
};

use crate::{
    inst::SwppInstKind,
    program::{SwppContext, SwppState},
    register::SwppRegisterSet,
};

#[cfg(not(feature = "log"))]
#[derive(Debug)]
pub struct SwppLogger {}

#[cfg(feature = "log")]
#[derive(Debug)]
pub struct SwppLogger {
    idx: u64,
    cur_tab: u64,
    base_log_writer: BufWriter<File>,
}

impl SwppLogger {
    #[cfg(not(feature = "log"))]
    pub fn new() -> Self {
        Self {}
    }

    #[cfg(feature = "log")]
    pub fn new(base_log_path: &str, mem_log_path: &str, op_log_path: &str) -> Self {
        let base_log_writer = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(base_log_path)
            .expect(&format!("Fail to open log file : {}", base_log_path));

        let mut base_log_writer = BufWriter::new(base_log_writer);

        let line = format!(
            "{:^6}|{:^20}|{:^8}|{:^4}|{:^10}|{:30}\n",
            "Index",
            "InstructionKind",
            "LineNum",
            "Cost",
            "TotalCost",
            "CurrentScope",
        );

        base_log_writer
            .write(line.as_bytes())
            .expect("Logging Error");

        Self {
            idx: 0,
            cur_tab: 0,
            base_log_writer,
        }
    }

    pub fn log(
        &mut self,
        line_num: u64,
        inst: &str,
        cost: u64,
        total_cost: u64,
        ctxt: &SwppContext,
    ) {
        #[cfg(feature = "log")]
        {
            let mut tab = String::new();
            

            let line = format!(
                "{:6}|{:^20}|{:8}|{:4}|{:10}|{:30}\n",
                self.idx,
                inst,
                line_num,
                cost,
                total_cost,
                ctxt.get_fname(),
            );

            self.base_log_writer
                .write(line.as_bytes())
                .expect("Logging Error");
            self.idx += 1;
        }
    }

    pub fn enter_fn(&mut self) {
        #[cfg(feature = "log")]
        {
            self.cur_tab += 1;
        }
    }

    pub fn exit_fn(&mut self) {
        #[cfg(feature = "log")]
        {
            self.cur_tab -= 1;
        }
    }
}
