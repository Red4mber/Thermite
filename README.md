# Thermite
## A Rust Malware development and EDR/AV Evasion Learning Project
This is a learning project aimed at exploring advanced topics in Windows internals, malware development and EDR/AV evasion techniques. The project is written entirely in Rust and so far does not include any Windows libraries. All structures and types have been defined by hand to facilitate learning and enable the use of undocumented data and functions.

## Disclaimer

This project is not intended for offensive or malicious purposes. It is solely for educational purposes and may not even be capable of performing any harmful actions in its current state. The primary goal is to understand and showcase various evasion techniques, not to attack or compromise systems.

## Features

1. **Simple Offensive Tasks**: The project can perform basic offensive tasks such as DLL injection and shellcode execution. These features serve as a foundation for understanding and implementing evasion techniques.

2. **EDR Evasion Techniques**:
- **Direct and Indirect Syscalls**: Demonstrates the use of direct and indirect system calls as a means of evading certain security measures.
- **Dynamic Syscall Retrieval**: Implements dynamic retrieval of system call addresses using techniques like Hell's Gate, Halo's Gate, and FreshyCalls.

3. **Pure Rust Implementation**: The entire project is written in pure Rust, without relying on any Windows libraries. This approach promotes a deeper understanding of low-level operations and enables experimentation with undocumented data and functions.

## Usage

This project is primarily intended for educational purposes and should be used in a controlled and responsible manner. It is not recommended to use this project on production systems or for any illegal activities.

## The Name
What is thermite if not offensive rust ?
<!-- 
I like Thermite, because what is thermite if not offensive rust ?
Or maybe something with books, because it's a learning project, like Palimpsest or arcanes or enchiridion idk 

-->
## Contributing

Contributions to this project are welcome. If you have any suggestions, improvements, or additional evasion techniques to explore, feel free to submit a pull request or open an issue.

## License

This project is licensed under the [Oops i forgot the license](). Feel free to do whatever you want until i pick a real one.

## Acknowledgments

This project would not have been possible without the invaluable resources and contributions from the Rust community and the cybersecurity research community. Special thanks to the authors and researchers whose work has inspired and guided the development of this project.
<!--
A huge thank you to [Alice Climent-Pommeret](https://alice.climent-pommeret.red/) who's many blog posts have been incredibly invaluable, i really couldn't have done this without her. Her blog is super well written and her explanations detailed and clear, i really advise anyone interested in teh subject who doesn't yet know her to go read it ASAP. 

We would like to express my sincere gratitude and respect for the late [Geoff Chappell](https://www.geoffchappell.com/index.htm), whose extensive documentation and insights into the obscure details of Windows internals have been an invaluable resource. His dedication to uncovering the inner workings of the operating system has been a guiding light for many in the field, and his work will continue to be an inspiration for future generations of researchers.

-->
