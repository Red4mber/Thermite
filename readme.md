# Thermite: Offensive Rust

A malware development project written entirely in Rust.

Despite the presentation as a library, only goal is to learn stuff, i don't really plan for it to be more than a collection of scripts and functions. 

## Summary

What is already done ?

* PEB Walking and enumeration using custom implementation of GetModuleHandle/GetProcAddress
* Direct syscalls with dynamic syscall ID retrieval using a mix of techniques such as Hell's Gates and Halo's Gate/Tartarus gate.
* Indirect syscalls (now with syscall sorting to retrieve SSNs o/)

I am also currently working on various other techniques such as process enumeration, etw/amsi patching, PPID spoofing etc... Everything is not online yet, but i try to update the repository as regularly as possible.

### Go check out the code :D

The goal of this project is to teach myself malware development, this is why I took care to document everything and wrote detailed comments and documentation.

For this reason i really invite anyone interested to go check out the code, I learned a lot while making this, maybe you could too, who knows ?

Knowledge is meant to be shared <3

## Why the name ?

What is thermite if not offensive rust ?

Also, it's cool and all cool projects need a cool name.

## License

Nah, take it

Just don't be evil :)
