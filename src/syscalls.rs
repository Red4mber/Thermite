use std::arch::global_asm;
use std::ptr;
use crate::dll_parser::{Export, get_all_exported_functions, get_module_address};
use crate::error::{DllParserError};

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


#[allow(unused)]
extern "C" {
    /// Our wrapper around syscall, imported from the assembly code above
    ///
    /// Takes the following arguments :
    ///  - `ssn` : An integer, the System Service Number of the syscall you want to call
    ///  - `n_args`: An integer, refers to the count of arguments to pass to syscall (excluding these two, which are not passed to syscall)
    ///  - ...  -> Then, every argument to pass to the syscall instruction.
    fn syscall_handler(
        ssn: u16,
        n_args: u32,
        ...
    ) -> i32;
}

// TODO: Macro wrapper around the syscall handler






/// Simply retrieves the 4th byte of the function, if the 3rd is a MOV EAX, <???> instruction.
/// If it's not, simply returns None
///
/// # Arguments
///
/// - `syscall_addr` : The address of the function we are looking for, can be obtained with [`get_function_address`]
///
/// Very simple way to find a ssn, but it works well if there's no hook
/// but it would absolutely shit the bed at the mere sight of an EDR, hence the name "simple"
///
pub fn simple_get_ssn(syscall_addr: *const u8) -> Option<u16> {
    unsafe {
        if ptr::read(syscall_addr.add(3)) == 0xB8 {
            Some(ptr::read(syscall_addr.add(4)) as u16)
        } else { None }
    }
}



/// Searches for every syscalls using the provided pattern
/// It then executes the find_ssn function on every one of them to retrieve their syscall numbers
///
/// Returns a vector of [Syscall] containing the matches
///
/// # Examples:
/// ```
/// let ssn_array = unsafe{
///      thermite::syscalls::search(|&x| {
///         x.name.starts_with("Nt")
///      }, thermite::syscalls::simple_get_ssn)
///  }.unwrap();
///
///  println!("[^-^] Done! I found {:#?} matching syscalls !", ssn_array.len());
///  if ssn_array.len() < 20 {
///      println!("{ssn_array:#x?}");
///  }
/// ```
pub fn search(
    pattern: fn(&&Export) -> bool,
    find_ssn: fn(*const u8) -> Option<u16>
) -> Result<Vec<Syscall>,DllParserError> {
    let ntdll_handle = unsafe { get_module_address("ntdll.dll") }?;

    let ssns = unsafe { get_all_exported_functions(ntdll_handle) }?
        .iter()
        .filter(pattern)
        .filter_map(|x| {
            find_ssn(x.address)
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