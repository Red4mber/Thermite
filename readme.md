# Thermite: Offensive Rust

## Summary 
:fr: \
Thermite est une bibliothèque de développement de logiciels malveillants écrite entièrement en Rust. \
Il implémente diverses techniques offensives telles que la marche PEB, les appels système directs et indirects, et le hooking par points d'arrêt matériels. Bien que présenté comme un outil d'apprentissage, le projet n'est pas destiné à une utilisation lors d'engagements réels.

:us: \
A malware development project written entirely in Rust. \
Thermite is a malware development library written entirely in Rust. It implements various offensive techniques such as PEB walking, direct and indirect system calls, and hardware breakpoint hooking. Although presented as a learning tool, the project is not intended for real-world use.



## A short disclaimer

Despite the presentation as a library, my only goal making this was to learn and I never really planned for it to be public I will probably not maintain it regularly, so expect a few bugs. \
However, do note that all [the examples](/examples/readme.md) included in the repository work and have been tested. 

### Core functionnalities

* **PEB Walking** and enumeration using custom implementation of GetModuleHandle/GetProcAddress
* **Direct syscalls** with dynamic syscall ID retrieval using a mix of techniques such as Hell's Gates and Halo's Gate/Tartarus gate.
* **Indirect syscalls** (now with syscall sorting to retrieve SSNs ! (a.k.a FreshyCalls))
* **API Hooking** using **Hardware breakpoints** - (Patchless AMSI Bypass using this technique)

I am also currently working on various other techniques such as process enumeration, etw/amsi patching, PPID spoofing etc… Everything is not online yet, but I try to update the repository as regularly as possible.

I suggest checking [the examples](/examples/readme.md), as most functionnalities are demonstrated by examples, but there's still quite a few that remains undocumented so I highly recommand to go check out the code by yourself.

In addition, I took a lot of care to **document everything** by **writing detailed comments and documentation**. The goal of this project is to teach myself malware development, and **knowledge is meant to be shared <3**

For this reason I invite anyone interested to go check out the code, I learned a lot while making this, maybe you could too.

## License

Nah, take it, just star the repo if you do :star:
