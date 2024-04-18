use std::{fs::File, io::Read, str::from_utf8};

use swpp_interpreter::{parser::total_program_parser, program::SwppProgram};

fn main() {
    let asm_path = std::env::args().nth(1).expect("no Assembly file link");

    let mut asm_file = File::options()
        .read(true)
        .open(&asm_path)
        .expect(&format!("Fail to open Assembly file : {}", asm_path));

    let mut buf = [0; 50000];

    let size = asm_file.read(&mut buf).expect("Fail to read assembly file");

    if size >= 50000 {
        panic!("Assembly longer than 50000 bytes is not supported")
    }

    let asm = from_utf8(&buf).expect("There is invalid character in assembly");
    #[cfg(feature = "log")]
    let mut program = SwppProgram::new(
        total_program_parser(asm),
        "./swpp-interpreter-basic.log",
        "./swpp-interpreter-mem.log",
        "./swpp-interpreter-op.log",
    );
    #[cfg(not(feature = "log"))]
    let mut program = SwppProgram::new(total_program_parser(asm));

    program.run().unwrap_or_else(|err| {
        println!(
            "Your assembly fails with following Error\n{}",
            err.to_string()
        );
        panic!()
    });

    println!("Final Cost : {}", program.total_cost())
}
