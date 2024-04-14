# Thermite: Offensive Rust

A malware development project written entirely in Rust.

Despite the presentation as a library, only goal is to learn stuff, I don't really plan for it to be more than a collection of scripts and functions. 
I mostly do it for the sake of learning cool stuff.

## Summary

What is done yet ?

* PEB Walking and enumeration using custom implementation of GetModuleHandle/GetProcAddress
* Direct syscalls with dynamic syscall ID retrieval using a mix of techniques such as Hell's Gates and Halo's Gate/Tartarus gate.
* Indirect syscalls (now with syscall sorting to retrieve SSNs o/)
* Hooking via Hardware breakpoints - (Patchless AMSI Bypass using this technique)

I am also currently working on various other techniques such as process enumeration, etw/amsi patching, PPID spoofing etc… Everything is not online yet, but I try to update the repository as regularly as possible.

Go checkl [the examples](/examples/readme.md) !

##### Just go check out the code :D

The goal of this project is to teach myself malware development, this is why I took care to document everything and wrote detailed comments and documentation.

For this reason I really invite anyone interested to go check out the code, I learned a lot while making this, maybe you could too, who knows ?

Knowledge is meant to be shared <3

## Why the name ?

What is thermite if not offensive rust ?

Also, it is cool and sounds better than "Random assortment of notes and programs vaguely related to malware"

## License

Nah, take it

Just don't be evil :)
