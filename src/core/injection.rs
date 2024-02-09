use std::error::Error;
use std::ffi::CString;
use std::ops::Add;
use std::path::Path;
use sysinfo::Process;
use process_memory::{DataMember, LocalMember, Memory, Pid, ProcessHandle, TryIntoProcessHandle};
use widestring::WideCString;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{BOOL, DWORD, LPDWORD, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{GetModuleHandleA, GetModuleHandleW};
use winapi::um::memoryapi::VirtualFreeEx;
use winapi::um::minwinbase::{LPSECURITY_ATTRIBUTES, LPTHREAD_START_ROUTINE, PTHREAD_START_ROUTINE, SECURITY_ATTRIBUTES};
use winapi::um::processthreadsapi::{CreateProcessA, OpenProcess};
use winapi::um::winnt::{CHAR, LPCSTR, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, PROCESS_ALL_ACCESS};

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
    InsufficientPermissions(String),
    PID(Box<dyn Error>),
    WriteMemory(Box<dyn Error>)
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
        let handle = match (self.process.pid().as_u32() as Pid).try_into_process_handle() {
            Ok(h) => h,
            Err(e) => return Err(InjectionError::PID(Box::new(e))),
        };

        let outcome = self.method.inject(self, handle)?;

        println!("Successfully injected at {:?}", outcome.memory_address.as_ref().unwrap());

        Ok(outcome)
    }
}

impl<'a> InjectionMethod {
    fn inject(&self, target: &'a Target, handle: ProcessHandle) -> anyhow::Result<InjectionOutcome, InjectionError> {
        match self {
            InjectionMethod::Standard => InjectionMethod::handle_standard(target, handle),
        }
    }

    fn handle_standard(target: &'a Target, handle: ProcessHandle) -> anyhow::Result<InjectionOutcome, InjectionError> {
        // Open Process
        let handle = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, BOOL::from(false), target.process.pid().as_u32())
        };

        // Allocate Memory
        println!("Allocating Memory");
        let mut state = target.dll_path.to_str().unwrap().to_string();
        let mut state_ptr = state.as_ptr().cast();
        let lp_dll_path = unsafe {
            winapi::um::memoryapi::VirtualAllocEx(handle.clone(), std::ptr::null_mut(), state.len(), MEM_COMMIT, PAGE_READWRITE)
        };
        println!("dll path: {:?}", lp_dll_path);

        // Write memory
        println!("Writing to  Memory");
        unsafe {
            let mut bw = 0;
            winapi::um::memoryapi::WriteProcessMemory(handle.clone(), lp_dll_path, *state_ptr, state.len(), &mut bw);
        }

        // Launch Thread
        println!("Launching Thread");
        let thread = unsafe {
            // let ker = CString::new("Kernel32").expect("CString Failed");
            let lla = CString::new("LoadLibraryA").expect("CString Failed");

            let ker = WideCString::from_str("Kernel32").expect("WideCString Failed");
            // let lla = WideCString::from_str("LoadLibraryA").expect("WideCString Failed");

            println!("Getting Kernel");
            let handle_a = GetModuleHandleW(ker.as_ptr());
            let err_d = GetLastError();
            println!("Getting process address");
            let proc_addr = winapi::um::libloaderapi::GetProcAddress(handle_a, lla.as_ptr());
            let err = GetLastError();
            let mut thread_id= 0;

            println!("Routine Cast");
            let routine = proc_addr.cast();

            println!("Creating remote thread");
            winapi::um::processthreadsapi::CreateRemoteThread(handle.clone(), std::ptr::null_mut(),0, *routine, lp_dll_path,0, &mut thread_id)
        };

        // Wait for thread to execute
        println!("Awaiting Thread to execute");
        unsafe {
            winapi::um::synchapi::WaitForSingleObject(thread, winapi::um::winbase::INFINITE);
        }

        // Free Memory
        println!("Freeing Memory");
        unsafe {
            VirtualFreeEx(handle.clone(), lp_dll_path, state.len() + 1, MEM_RELEASE);
        }

        let outcome = InjectionOutcome {
            memory_address: Some(hex::encode((thread as u32).to_string()))
        };

        Ok(outcome)
    }
}