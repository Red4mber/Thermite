// This place is not a place of honor...
// no highly esteemed deed is commemorated here...
// nothing valued is here.


/// Stuff to deal with the PEB and TEB structures in windows
/// Rather incomplete but also the less used of the two
pub mod peb_teb;

/// All the data structures used to parse DLLs
/// Really the only one of the two modules which is at least a little bit useful
pub mod pe_file_format;