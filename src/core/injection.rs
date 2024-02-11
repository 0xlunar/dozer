use std::ffi::CString;
use std::path::Path;
use sysinfo::Process;
use winapi::shared::minwindef::{BOOL, DWORD, LPVOID};
use winapi::um::libloaderapi::{GetModuleHandleA};
use winapi::um::memoryapi::{VirtualFreeEx, VirtualProtectEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{OpenProcess};
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS};
use crate::core::injection::InjectionError::{NullProcess, WriteMemory};

pub enum InjectionMethod {
    Standard,
}

pub struct Target<'a> {
    process: &'a Process,
    dll_path: &'a Path,
    method: InjectionMethod,
}

#[derive(Default)]
pub struct InjectionOutcome {
    pub memory_address: Option<String>,
}

#[derive(Debug)]
pub enum InjectionError {
    WriteMemory(&'static str),
    NullProcess(&'static str)
}

impl<'a> Target<'a> {
    pub fn new(process: &'a Process, dll_path: &'a Path, method: InjectionMethod) -> Self {
        Self {
            process,
            dll_path,
            method
        }
    }

    pub fn inject(&self) -> anyhow::Result<InjectionOutcome, InjectionError> {
        println!("Injecting...");
        self.method.inject(self)
    }
}

impl<'a> InjectionMethod {
    fn inject(&self, target: &'a Target) -> anyhow::Result<InjectionOutcome, InjectionError> {
        match self {
            InjectionMethod::Standard => InjectionMethod::handle_standard(target),
        }
    }

    fn handle_standard(target: &'a Target) -> anyhow::Result<InjectionOutcome, InjectionError> {
        // Open Process
        let handle = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, BOOL::from(false), target.process.pid().as_u32())
        };

        if handle.is_null() {
            return Err(NullProcess("Process is not active"))
        }

        // Allocate Memory
        let state = CString::new(target.dll_path.to_str().unwrap().to_string()).expect("CString::new Failed");
        let lp_dll_path = unsafe {
            winapi::um::memoryapi::VirtualAllocEx(handle, std::ptr::null_mut(), state.as_bytes_with_nul().len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        };

        unsafe {
            if !InjectionMethod::patch_memory(handle, lp_dll_path, state.as_bytes_with_nul()) {
                return Err(WriteMemory("Failed to write dll to memory"))
            }
        }

        let thread = unsafe {
            let ker = CString::new("kernel32.dll").expect("CString::new Failed");
            let lla = CString::new("LoadLibraryA").expect("CString::new Failed");

            let handle_a = GetModuleHandleA(ker.as_ptr());
            if handle_a.is_null() {
                return Err(NullProcess("kernel32.dll failed"));
            }

            let proc_addr = winapi::um::libloaderapi::GetProcAddress(handle_a, lla.as_ptr());
            if proc_addr.is_null() {
                return Err(NullProcess("LoadLibraryA failed"));
            }

            winapi::um::processthreadsapi::CreateRemoteThread(handle, std::ptr::null_mut(),0, Some(std::mem::transmute(proc_addr)), lp_dll_path as *mut _,0, std::ptr::null_mut())
        };

        if thread.is_null() {
            return Err(NullProcess("CreateRemoteThread Failed"));
        }

        let outcome = InjectionOutcome {
            memory_address: Some(format!("{:p}", thread))
        };

        unsafe {
            if winapi::um::handleapi::CloseHandle(thread) != 1 {
                return Err(NullProcess("Failed to Close Handle"))
            }
        }

        // Free Memory
        unsafe {
            VirtualFreeEx(handle, lp_dll_path, state.as_bytes_with_nul().len(), MEM_RELEASE);
        }

        println!("Injected!");

        Ok(outcome)
    }

    unsafe fn patch_memory(handle: HANDLE, address: LPVOID, data: &[u8]) -> bool {
        let mut old_prot: DWORD = 0;
        if VirtualProtectEx(handle, address, data.len() + 1, PAGE_EXECUTE_READWRITE, &mut old_prot) != 0 {
            let mut b_w = 0;
            if WriteProcessMemory(handle, address, data.as_ptr() as *const _, data.len(), &mut b_w) != 0 {
                return true;
            }
        }

        false
    }
}