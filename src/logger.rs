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
    base_log_writer: File,
    mem_log_writer: File,
    op_log_writer: File,
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

        let mem_log_writer = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(mem_log_path)
            .expect(&format!("Fail to open log file : {}", mem_log_path));

        let op_log_writer = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(op_log_path)
            .expect(&format!("Fail to open log file : {}", op_log_path));

        Self {
            idx: 0,
            cur_tab: 0,
            mem_log_writer,
            op_log_writer,
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
            for _ in 0..self.cur_tab - 1 {
                tab += "\t"
            }

            let line = format!(
                "{}{:6}|{:^20}|{:4}|{:3}|{:10}|{:30}\n",
                &tab,
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

    pub fn log_verbose(&mut self, reg_set: &SwppRegisterSet) {
        #[cfg(any(feature = "verbose_log", feature = "total_log"))]
        {
            let reg_str = format!("{:?}\n", reg_set.print_gen_register());
            self.base_log_writer
                .write(reg_str.as_bytes())
                .expect("Logging Error");
        }
    }

    pub fn log_mem_trace(&mut self, log: String) {
        #[cfg(feature = "verbose_log")]
        {
            self.mem_log_writer
                .write(log.as_bytes())
                .expect("Logging Error");
        }
        #[cfg(feature = "total_log")]
        {
            self.base_log_writer
                .write(log.as_bytes())
                .expect("Logging Error");
        }
    }

    pub fn log_op(&mut self, log: String) {
        #[cfg(feature = "verbose_log")]
        {
            self.op_log_writer
                .write(log.as_bytes())
                .expect("Logging Error");
            self.op_log_writer
                .write("\n".as_bytes())
                .expect("Logging Error");
        }

        #[cfg(feature = "total_log")]
        {
            self.base_log_writer
                .write(log.as_bytes())
                .expect("Logging Error");
            self.base_log_writer
                .write("\n".as_bytes())
                .expect("Logging Error");
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
