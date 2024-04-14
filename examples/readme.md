# Examples
Some examples areare full-fledged programs showcasing interesting techniques while others are “scratchpads” or sketches of functionnalities I plan to add in the library in the future.

All the examples here can be compiled and launched using cargo from the root directory of this project.
You can just run `cargo run --example` without specifying an example to get a list of all available examples to run.
### A [DLL Injector](/examples/dll_injector.rs) and a [Shellcode Injector](/examples/shellcode_injector.rs)

Aims to demonstrate how to perform a DLL/Shellcode injection using syscalls 
using direct syscalls.
```bash
cargo run --package thermite --example dll_injector <Target PID> C:\absolute\path\to\your.dll
```

### [Hooking via Hardware Breakpoints](/examples/hardware_breakpoints.rs)

This example demonstrates the use of hardware breakpoints for hooking.

This technique is then put to use in the [patchless AMSI Bypass](patchless_amsi_bypass.rs) example, which demonstrates how to bypass AMSI by hooking the AMSIScanBuffer function using hardware breakpoints.

### [SystemFunction032](/examples/systemfunction032.rs)

This example demonstrates how to use SystemFunction032, an undocumented windows internals function, to decrypt a RC4 encrypted shellcode.


### The other stuff

#### [FreshyCalls](/examples/freshycalls.rs) and [Halo's Gate](/examples/halos_gate.rs)

The FreshyCalls example shows how to dynamically retrieve syscall IDs by sorting syscalls by address, then assigning them
all an ID in order.
This example also includes code to verify the IDs are valid.

Halo's Gate (also called tartarus gate) is a technique that use known syscall IDs to extrapolate the IDs of hooked syscalls we can't retrieve directly.
This is the technique is use in the main library if a hooked syscall is detected.

### The other other stuff

Consists mostly of simple notes, scripts and stuff like that i keep around just to have on hand if i need it.

I mostly develop this project though examples, meaning i'll code the example, then extract the functyionnaliities used in the example in the main library.
So there will be a lot of unfinished stuff laying around there, feel free to take a look. 
