///////////////////////////////////////////////////////////
//
//             -- Thermite: Offensive Rust --
//                   MODELS Module File
//
//            Reunites all the different files
//         storing data models in a single module
//
//          Made by RedAmber - 27 March 2024
///////////////////////////////////////////////////////////


/// Stuff to deal with the PEB and TEB structures in windows
/// Rather incomplete but also the less used of the two
pub mod peb_teb;


/// All the data structures used to parse PE Files
/// Used in almost every function so far as most of them deal with DLLs
pub mod pe_file_format;
