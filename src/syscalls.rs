#![allow(unused)]
use std::arch::global_asm;
use std::ptr;
use crate::dll_parser::{get_all_exported_functions, get_function_address, get_module_address};
use crate::error::{DllParserError, ThermiteError};
use crate::error::SyscallError::SSNNotFound;
use crate::error::ThermiteError::SyscallError;


#[derive(Debug, Clone)]
pub struct Syscall {
    pub name: String,
    pub address: *const u8,
    pub ssn: u16,
}
/*
We cannot use the usual syscall stub such as you would find in NTDLL.dll
```asm
mov r10,rcx
mov eax,[ssn]
syscall
ret
```
Because we cannot dynamically generate the assembly code and execute it at runtime
So we need to craft an assembly function that can take the SSN as parameters, which then
causes all the arguments to end up in the next register.

When calling a function on windows the arguments are passed like this : (except for floats, but that irrelevant for syscalls)
In left-to-right order, in RCX, RDX, R8, and R9,
The fifth and higher arguments are called stack parameters, they will be pushed on the stack
RSP+28, +30, +32 etc...

We need them in this order before executing the syscall instruction, so we need to move them back
The only exception being the first parameter, which goes in r10 for all syscalls (even in the NTDLL code)
the first four are easy to deal with, but the stack parameters demand more work

But by decrementing the number of arguments by 4, we have the number of stack parameters
We store it the RCX register because it is the counter for the REP instruction, that will repeat the MOVSQ instruction
MOVSQ will then repeat until RCX reaches zero

It's quite a brilliant solution and I take absolutely zero credit for it, go check janoglezcampos on GitHub, that's where I found this

because the code had no comments and I suck hard at assembly,
It took me a whole day just to figure out how it worked, so now I'm leaving comments everywhere

Block comments can be folded on most editors, so there's nothing to lose
*/
global_asm!(r#"
.global syscall_handler
.section .text

syscall_handler:
    mov [rsp - 0x8],  rsi       // Backup the value of RSI to the stack
    mov [rsp - 0x10], rdi       // Backup the value of RDI to the stack

    mov eax, ecx                // Move the sycall number to RAX
    mov rcx, rdx                // Move the arguments number in RCX

    mov r10, r8                 // Move Arg1 in R10                         // syscall overwrite RCX so Arg1 goes to r10
    mov rdx, r9                 // Move Arg2 in RDX
    mov  r8,  [rsp + 0x28]      // Move Arg3 in R8
    mov  r9,  [rsp + 0x30]      // Move Arg4 in R9

    sub rcx, 0x4                // Substract 4 from RCX                     // Do we have stack params ?
    jle execute                 // If zero or less, skip to the end         // If yes

    lea rsi,  [rsp + 0x38]      // Move the address of [rsp + 0x38] in RSI
    lea rdi,  [rsp + 0x28]      // Move the address of [rsp + 0x28] in RDI

    rep movsq                   // Move qword RSI to RDI, repeat RCX times  // Move them down
execute:
    syscall                     // Perform the Syscall

    mov rsi, [rsp - 0x8]        // Restore value of RSI
    mov rdi, [rsp - 0x10]       // Restore value of RDI
    ret                         // Return
"#);

extern "C" {
    fn syscall_handler(
        ssn: u16,
        n_args: u32,
        ...
    ) -> i32;
}

/// TODO - Do another one, but better :D
///
/// Very simple way to find a ssn, but it works well if there's no hook
///
/// A normal syscall stub look like :
/// 4C 8B D1           : MOV R10,RCX
/// B8 ?? 00 00 00     : MOV EAX,SSN
///
/// We're looking for the SSN, so the 4th byte, just following 0xB8
pub unsafe fn simple_get_ssn(syscall_name: &str) -> Result<u16, ThermiteError> {
    let ntdll_handle= get_module_address("ntdll.dll")
        .map_err(|e| { ThermiteError::DllParserError(e) })?;
    let start_ptr = get_function_address(syscall_name, ntdll_handle)
        .map_err(|e| { ThermiteError::DllParserError(e) })?;

    if ptr::read(start_ptr.add(3)) == 0xB8 {    // Check if third byte is MOV EAX, so we don't read random values if it isn't
        Ok((ptr::read(start_ptr.add(4)) as u16))//
    } else {
        Err(SyscallError(SSNNotFound))
    }
}

// TODO : Finish this - Do you really want a dyn ?
pub fn get_all_ssn(_f: &dyn Fn(&str) -> u16) -> Result<Vec<Syscall>,DllParserError> {
    let ntdll_handle = unsafe { get_module_address("ntdll.dll") }?;

    let ssns = unsafe { get_all_exported_functions(ntdll_handle) }?
        .iter()
        .filter(|&x| {
            x.name.starts_with("Zw")
        })
        .filter_map(|x| { unsafe { simple_get_ssn(x.name.as_str()) }.ok()
            .map(|ssn| {
                Syscall {
                    name: x.name.clone(),
                    address: x.address,
                    ssn
                }
            })
        })
        .collect();
    return Ok(ssns)
}




// TODO : Document this module properly
// Not just with random-ass comments