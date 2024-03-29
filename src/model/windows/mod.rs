// This place is not a place of honor...
// no highly esteemed deed is commemorated here...
// nothing valued is here.

/// Stuff to deal with the PEB and TEB structures in windows
/// Rather incomplete but also the less used of the two
pub mod peb_teb;

/// All the data structures used to parse DLLs
/// Really the only one of the two modules which is at least a little bit useful
pub mod pe_file_format;

// A single enum with 3000 variants to match NT_STATUS to actual legible errors
pub mod nt_status;


// MASSIVE TODO: Clean up all these modules and remove everything unused
// Todo two : Reformat / Refactor both modules to respect rusts naming convention and make it easier to read
