# Thermite: Offensive Rust

A malware development project written entirely in Rust.

Despite the presentation as a library, my only goal is to learn, so I never planned for this library to be of use to anyone and I will probably not maintain it regularly, expect bugs and broken functionnalities. However, all the examples included in the repository work and have been tested. 

## Summary

What is done yet ?

* PEB Walking and enumeration using custom implementation of GetModuleHandle/GetProcAddress
* Direct syscalls with dynamic syscall ID retrieval using a mix of techniques such as Hell's Gates and Halo's Gate/Tartarus gate.
* Indirect syscalls (now with syscall sorting to retrieve SSNs o/)
* Hooking via Hardware breakpoints - (Patchless AMSI Bypass using this technique)

I am also currently working on various other techniques such as process enumeration, etw/amsi patching, PPID spoofing etc… Everything is not online yet, but I try to update the repository as regularly as possible.

##### Just go check out the code :D

Go checkl [the examples](/examples/readme.md) !

The goal of this project is to teach myself malware development, this is why I took care to document everything and wrote detailed comments and documentation.

Knowledge is meant to be shared <3

For this reason I invite anyone interested to go check out the code, I learned a lot while making this, maybe you could too.

## License

Nah, just take it and just star the repo if you like it.
