use std::path::Path;
use sysinfo;
use sysinfo::System;
use crate::core::injection::InjectionMethod::Standard;
use clap::Parser;

mod core;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Arguments {
    #[arg(short, long)]
    name: String,
    #[arg(short, long)]
    dll: String,
}

fn main() {
    let args = Arguments::parse();

    let system = System::new_all();
    let pid = match system.processes_by_name(&args.name).next() {
        Some(t) => t,
        None => {
            println!("Process not found");
            std::process::exit(0);
        }
    };

    println!("Targeting: {}, PID: {}", pid.name(), pid.pid().as_u32());

    let dll = Path::new(&args.dll);
    let target = core::injection::Target::new(pid, dll, Standard);
    match target.inject() {
        Ok(t) => println!("Outcome: {:?}", t.memory_address),
        Err(e) => println!("Error: {:?}", e),
    }
}

