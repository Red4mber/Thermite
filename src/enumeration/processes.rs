use crate::info;
use crate::models::windows::system_info::SystemProcessInformation;
use crate::models::windows::system_info::SystemInformationClass;
use crate::indirect_syscall as syscall;
use crate::models::windows::{NT_CURRENT_PROCESS, PAGE_EXECUTE_READWRITE, MEM_RESERVE, MEM_COMMIT};


/// This function returns a pointer to the system process information table.
///
/// It will perform system calls to `NtQuerySystemInformation` and `NtAllocateVirtualMemory`
///
/// # Returns  
/// A raw pointer to the [SystemProcessInformation] table.
pub fn get_process_info_ptr() -> *const SystemProcessInformation {
	let mut buffer: *mut std::ffi::c_void = 0u32 as _;
	let mut buf_size: isize = 0;

	let info_class = SystemInformationClass::SystemProcessInformation;
	// We need to call the NtQuerySystemInformation once to get the size of the buffer needed to store its output
	syscall!("NtQuerySystemInformation",
	    info_class,                    // [in]            SystemInformationClass SystemInformationClass // (0x05) for processes
	    0,                             // [in, out]       PVOID                    SystemInformation,
	    0,                             // [in]            ULONG                    SystemInformationLength,
	    &mut buf_size);                // [out, optional] PULONG                   ReturnLength

	// We now need to allocate a buffer for the result of the function
	syscall!("NtAllocateVirtualMemory",
        NT_CURRENT_PROCESS,         // [in]      HANDLE    ProcessHandle,
        &mut buffer,                // [in, out] PVOID     *BaseAddress,
        0u32,                       // [in]      PULONG    ZeroBits,
        &mut buf_size,              // [in, out] PSIZE_T   RegionSize,
        MEM_COMMIT | MEM_RESERVE,   // [in]      ULONG     AllocationType,
        PAGE_EXECUTE_READWRITE);
	// [in]      ULONG     Protect
	info!("Allocated {} bytes of memory at address {:#x?}", buf_size, buffer);

	// We can now make a second call, this time with teh memory already allocated to store the result
	let mut buf_size_2: isize = 0;
	syscall!("NtQuerySystemInformation",
	    info_class, // [in]            SystemInformationClass SystemInformationClass,
	    buffer as *mut _,              // [in, out]       PVOID                    SystemInformation,
	    buf_size,                      // [in]            ULONG                    SystemInformationLength,
	    &mut buf_size_2);              // [out, optional] PULONG                   ReturnLength

	(buffer as *mut _) as *const SystemProcessInformation
}
