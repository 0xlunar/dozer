use std::path::Path;
use std::time::Duration;
use sysinfo;
use sysinfo::System;
use crate::core::injection::InjectionMethod::Standard;

mod core;

fn main() {
    let system = System::new_all();
    let pid = match system.processes_by_name("injector_test").next() {
        Some(t) => t,
        None => {
            panic!("Process not found");
        }
    };

    let dll = Path::new("E:\\PROJECTS\\TOOLS\\example_dll\\target\\release\\example_dll.dll");
    let target = core::injection::Target::new(pid, dll, Standard);
    match target.inject() {
        Ok(t) => println!("Outcome: {:?}", t.memory_address),
        Err(e) => println!("Error: {:?}", e),
    }

    std::thread::sleep(Duration::from_secs(10));
}

