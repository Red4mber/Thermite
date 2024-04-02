use std::arch::global_asm;
use std::ptr;
use crate::peb_walk::{get_all_exported_functions, get_module_address};



// https://stackoverflow.com/questions/49928950/acceptability-of-regular-usage-of-r10-and-r11
// https://www.reddit.com/r/asm/comments/j4mofq/why_cant_you_clobber_certain_registers/
// R12 -> R15 => Non clobbered
//
global_asm!(
    r#"
.global indirect_stub
.section .text

indirect_stub:
    mov [rsp - 0x8],  rsi       // Backup the value of RSI to the stack
    mov [rsp - 0x10], rdi       // Backup the value of RDI to the stack
    mov [rsp - 0x18], r12       // Backup the value of r12 to the stack
    mov eax, ecx                // Move the sycall number to RAX
    mov rcx, rdx                // Move the arguments number in RCX
    mov r12, r8                 // Move the syscall address to r12
    mov r10, r9                 // Move syscall Arg1 in R10
    mov rdx, [rsp + 0x28]       // Move syscall Arg2 in RDX
    mov  r8,  [rsp + 0x30]      // Move syscall Arg3 in R8
    mov  r9,  [rsp + 0x38]      // Move syscall Arg4 in R9

    sub rcx, 0x4                // Substract 4 from RCX
    jle indirect_execute        // If zero or less, skip to the end

    lea rsi,  [rsp + 0x40]      // Move the address of [rsp + 0x38] in RSI
    lea rdi,  [rsp + 0x28]      // Move the address of [rsp + 0x28] in RDI

    rep movsq                   // Move qword from [RSI] to [RDI], repeat RCX times  // Move every stack parameter "down"
indirect_execute:
    mov rcx, r12                // We don't need rcx, so move r12 to rcx so we can restore r12
    mov rsi, [rsp - 0x8]        // Restore value of RSI
    mov rdi, [rsp - 0x10]       // Restore value of RDI
    mov r12, [rsp - 0x18]       // Restore value of RDI
    jmp rcx
"#
);

extern "C" {
    /// Imported from the assembly code above
    ///
    /// Not really made to be called directly, it is better to use the [`thermite::syscall`] macro.
    ///
    /// ### Arguments :
    ///  - `ssn` : 16-bit unsigned int, the System Service Number of the syscall you want to call
    ///  - `arg_count`: 32-bit unsigned int, refers to the count of arguments to pass to syscall (excluding these two, which are not passed to syscall)
    ///  - `syscall address`: the address of a syscall instruction where to jump
    ///  - ...  -> Then, every argument to pass to the syscall instruction.
    pub fn indirect_stub(ssn: u16, arg_count: u32, addr: *const u8, ...) -> i32;
}


//          4C 8B D1                 //  mov r10,rcx
//          B8 ?? ?? 00 00           //  mov eax,1
//          F6 04 25 08 03 FE 7F 01  //  test byte ptr ds:[7FFE0308],1
//          75 03                    //  jne ntdll.7FFACE92F395
//          0F 05                    //  syscall
//     SSN @ +4  Bytes
//    Test @ +8  Bytes
//    Jump @ +16 Bytes
// Syscall @ +18 Bytes
pub unsafe fn find_syscall_address(addr: *const u8) -> Option<*const u8> {
    let syscall_ptr = addr.byte_offset(18);
    match unsafe { ptr::read(syscall_ptr as *const [u8; 2]) } {
        [0x0f, 0x05] => { Some(syscall_ptr) },
        _ => { None }
    }
}


#[macro_export]
macro_rules! indirect_syscall {
    ($name:literal $(, $args:expr)* $(,)?) => {
         unsafe {
            $crate::syscalls::indirect::indirect_stub(
                $crate::syscalls::find_single_ssn($name).unwrap(),
                thermite::count_args!($($args),*),
                $crate::syscalls::indirect::find_single_syscall_addr(),
                $($args),*
            )
        };
    }
}


// TODO Refactor that disgusting mess
pub unsafe fn find_single_syscall_addr() -> *const u8 {
    let mut iter = get_all_exported_functions(
        get_module_address("ntdll.dll").unwrap()
    ).expect("Function not found in the export table");
    let aa = iter.iter().find(|x| {
        let syscall_ptr = x.address.byte_offset(18);
        ptr::read(syscall_ptr as *const [u8; 2]).eq(&[0x0f, 0x05])
    }).unwrap();
    aa.address.byte_offset(18)
}


