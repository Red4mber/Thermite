use std::arch::global_asm;
use std::ffi::c_void;
use thermite::{debug, info};

use std::mem;
use thermite::models::windows::peb_teb::UNICODE_STRING;
use thermite::syscalls::find_single_ssn;


const SYNCHRONIZE: u32 = 0x00100000u32;
const STANDARD_RIGHTS_REQUIRED: u32 = 0x00100000u32;
const PROCESS_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;



global_asm!(
    r#"
.global syscall_stub
.global syscall_prep
.section .text

syscall_stub:
mov r10,rcx
mov eax,r12
syscall
ret

syscall_prep:
mov rcx, r12
ret
"#
);


extern "C" {
	pub fn syscall_stub(a:&isize, ...) -> i32;
	pub fn syscall_prep(ssn: u16);
}
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct ObjectAttributes {
	length: u32,
	root_directory: isize,
	//Handle,
	object_name: *const UNICODE_STRING,
	attributes: u32,
	security_descriptor: *const c_void,
	//CVoid,
	security_quality_of_service: *const c_void,
}
#[repr(C)]
#[derive(Debug)]
pub struct ClientId {
	pub unique_process: isize,
	pub unique_thread: isize,
}

unsafe fn test() {
	let mut thread_handle: isize = 0;
	let oa_process: ObjectAttributes = ObjectAttributes {
		length: mem::size_of::<ObjectAttributes>() as _,
		root_directory: 0u32 as _,
		object_name: 0u32 as _,
		attributes: 0,
		security_descriptor: 0u32 as _,
		security_quality_of_service: 0u32 as _,
	};
	let mut process_handle: isize = -1;
	let client_id = ClientId {
		unique_process: 18744 as _,
		unique_thread: 0 as _,
	};
	let ssn = find_single_ssn("NtOpenProcess").unwrap();
	syscall_prep(ssn);
	let nt_status = syscall_stub(
            &mut process_handle, //  [out]          PHANDLE            ProcessHandle,
            PROCESS_ALL_ACCESS,  //  [in]           ACCESS_MASK        DesiredAccess,
            &oa_process,         //  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
            &client_id,          //  [in, optional] PCLIENT_ID         ClientId
        );
	info!("NtOpenProcess: {}", nt_status);
	debug!(process_handle);
}

fn main() {
	unsafe { test(); }
}