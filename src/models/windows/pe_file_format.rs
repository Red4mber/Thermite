/// All of these types are useful in some way for parsing PE Files, most specifically DLLs
///
/// All the structures are marked with `#[repr(C)]` to ensure that they are laid out in memory
/// exactly the same way as the corresponding C structure.This is necessary for
/// interoperability with other languages and systems that follow the C Application
/// Binary Interface (ABI).

//------------------------------------------------------------------
//
//              CONSTANTS
//
//------------------------------------------------------------------
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
// MZ
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
// PE00
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;
// PE File is a ROM
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
// PE32
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b; // PE32+

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;


// type definitions for 64-bits address space
//
#[cfg(target_pointer_width = "64")]
pub type ImageNtHeaders = ImageNtHeaders64;
#[cfg(target_pointer_width = "64")]
pub type ImageOptionalHeader = ImageOptionalHeader64;
#[cfg(target_pointer_width = "64")]
pub type PImageOptionalHeader = *mut ImageOptionalHeader64;


#[cfg(target_pointer_width = "64")]
pub const IMAGE_NT_OPTIONAL_HDR_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;


// type definitions for 32-bits address space
//
#[cfg(not(target_pointer_width = "64"))]
pub type ImageNtHeaders = ImageNtHeaders32;
#[cfg(not(target_pointer_width = "64"))]
pub type ImageOptionalHeader = ImageOptionalHeader32;
#[cfg(not(target_pointer_width = "64"))]
pub type PImageOptionalHeader = *mut ImageOptionalHeader32;


#[cfg(not(target_pointer_width = "64"))]
pub const IMAGE_NT_OPTIONAL_HDR_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR32_MAGIC;


//------------------------------------------------------------------
//
//              PE File headers
//
//------------------------------------------------------------------

/// Dos Header
///
/// Represents the first bytes of any PE files
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageDosHeader {
	/// magic number
	pub e_magic: u16,
	/// Bytes on last page of file
	pub e_cblp: u16,
	/// Pages in file
	pub e_cp: u16,
	/// Relocations
	pub e_crlc: u16,
	/// size of header in paragraphs
	pub e_cparhdr: u16,
	/// Minimum extra paragraphs needed
	pub e_minalloc: u16,
	/// Maximum extra paragraphs needed
	pub e_maxalloc: u16,
	/// Initial (relative) SS value
	pub e_ss: u16,
	/// Initial SP value
	pub e_sp: u16,
	/// Checksum
	pub e_csum: u16,
	/// Initial IP value
	pub e_ip: u16,
	/// Initial (relative) CS value
	pub e_cs: u16,
	/// File address of relocation table
	pub e_lfarlc: u16,
	/// Overlay number
	pub e_ovno: u16,
	/// Reserved words
	pub e_res: [u16; 4],
	/// OEM identifier
	pub e_oemid: u16,
	/// OEM information
	pub e_oeminfo: u16,
	/// Reserved words
	pub e_res2: [u16; 10],
	/// File address of the PE header
	pub e_lfanew: u32,
}


//
// 64-bits architecture-specific structures
//
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageNtHeaders64 {
	pub signature: u32,
	pub file_header: ImageFileHeader,
	pub optional_header: ImageOptionalHeader64,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageOptionalHeader64 {
	pub magic: u16,
	pub major_linker_version: u8,
	pub minor_linker_version: u8,
	pub size_of_code: u32,
	pub size_of_initialized_data: u32,
	pub size_of_uninitialized_data: u32,
	pub address_of_entry_point: u32,
	pub base_of_code: u32,
	pub image_base: u64,
	pub section_alignment: u32,
	pub file_alignment: u32,
	pub major_operating_system_version: u16,
	pub minor_operating_system_version: u16,
	pub major_image_version: u16,
	pub minor_image_version: u16,
	pub major_subsystem_version: u16,
	pub minor_subsystem_version: u16,
	pub win32version_value: u32,
	pub size_of_image: u32,
	pub size_of_headers: u32,
	pub check_sum: u32,
	pub subsystem: ImageSubsystem,
	pub dll_characteristics: u16,
	pub size_of_stack_reserve: u64,
	pub size_of_stack_commit: u64,
	pub size_of_heap_reserve: u64,
	pub size_of_heap_commit: u64,
	pub loader_flags: u32,
	pub number_of_rva_and_sizes: u32,
	pub data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

//
// 32-bits architecture specific structures
//

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageNtHeaders32 {
	pub signature: u32,
	pub file_header: ImageFileHeader,
	pub optional_header: ImageOptionalHeader32,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageOptionalHeader32 {
	pub magic: u16,
	pub major_linker_version: u8,
	pub minor_linker_version: u8,
	pub size_of_code: u32,
	pub size_of_initialized_data: u32,
	pub size_of_uninitialized_data: u32,
	pub address_of_entry_point: u32,
	pub base_of_code: u32,
	pub base_of_data: u32,
	pub image_base: u32,
	pub section_alignment: u32,
	pub file_alignment: u32,
	pub major_operating_system_version: u16,
	pub minor_operating_system_version: u16,
	pub major_image_version: u16,
	pub minor_image_version: u16,
	pub major_subsystem_version: u16,
	pub minor_subsystem_version: u16,
	pub win32version_value: u32,
	pub size_of_image: u32,
	pub size_of_headers: u32,
	pub check_sum: u32,
	pub subsystem: ImageSubsystem,
	pub dll_characteristics: u16,
	pub size_of_stack_reserve: u32,
	pub size_of_stack_commit: u32,
	pub size_of_heap_reserve: u32,
	pub size_of_heap_commit: u32,
	pub loader_flags: u32,
	pub number_of_rva_and_sizes: u32,
	pub data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}


//
//  OTHER GENERAL STRUCTURES FOR PE FILES
//
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageFileHeader {
	pub machine: u16,
	pub number_of_sections: u16,
	pub time_date_stamp: u32,
	pub pointer_to_symbol_table: u32,
	pub number_of_symbols: u32,
	pub size_of_optional_header: u16,
	pub characteristics: u16, // image_file_characteristics - 4 Bytes Bit flags - Refer to the corresponding module for more information
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageDataDirectory {
	pub virtual_address: u32,
	pub size: u32,
}


/// This structure describes the export information for a Dynamic Link Library (DLL).
/// It is used to provide information about the exported functions and their addresses.
///
/// All "AddressOf" fields are RVA, Relative Virtual Addresses
/// They are offsets, in bytes, from the base address of the DLL.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ImageExportDirectory {
	pub characteristics: u32,
	pub time_date_stamp: u32,
	pub major_version: u16,
	pub minor_version: u16,
	pub name: u32,
	pub base: u32,
	pub number_of_functions: u32,
	pub number_of_names: u32,
	pub address_of_functions: u32,
	pub address_of_names: u32,
	pub address_of_name_ordinals: u32,
}


//------------------------------------------------------------------
//   > BITFLAGS
//
//  C-Style bitflags don't exist natively in rust
// They're modules because enums wouldn't be 
// There is a crate that adds bitflags, but i don't want dependencies 
//------------------------------------------------------------------

/// characteristics of the image
pub mod image_file_characteristics {
	/// Relocation info stripped from file
	pub const RELOCS_STRIPPED: u16 = 0x0001;

	/// File is executable (i.e. no unresolved external references)
	pub const EXECUTABLE_IMAGE: u16 = 0x0002;

	/// Line numbers stripped from file
	pub const LINE_NUMS_STRIPPED: u16 = 0x0004;

	/// Local symbols stripped from file
	pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;

	/// Aggressively trim working set
	pub const AGGRESIVE_WS_TRIM: u16 = 0x0010;

	/// App can handle >2gb addresses
	pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;

	/// Bytes of machine word are reversed
	pub const BYTES_REVERSED_LO: u16 = 0x0080;

	/// 32-bit word machine
	pub const _32BIT_MACHINE: u16 = 0x0100;

	/// Debugging info stripped from file in .DBG file
	pub const DEBUG_STRIPPED: u16 = 0x0200;

	/// If Image is on removable media, copy and run from the swap file
	pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;

	/// If Image is on Net, copy and run from the swap file
	pub const NET_RUN_FROM_SWAP: u16 = 0x0800;

	/// System File
	pub const SYSTEM: u16 = 0x1000;

	/// File is a DLL
	pub const DLL: u16 = 0x2000;

	/// File should only be run on a UP machine
	pub const UP_SYSTEM_ONLY: u16 = 0x4000;

	/// Bytes of machine word are reversed
	pub const BYTES_REVERSED_HI: u16 = 0x8000;
}


/// dll_characteristics Entries
pub mod image_dll_characteristics {
	/// Reserved.
	pub const IMAGE_LIBRARY_PROCESS_INIT: u16 = 0x0001;

	/// Reserved.
	pub const IMAGE_LIBRARY_PROCESS_TERM: u16 = 0x0002;

	/// Reserved.
	pub const IMAGE_LIBRARY_THREAD_INIT: u16 = 0x0004;

	/// Reserved.
	pub const IMAGE_LIBRARY_THREAD_TERM: u16 = 0x0008;

	/// Image can handle a high entropy 64-bit virtual address space.
	pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;

	/// DLL can move.
	pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;

	/// Code Integrity Image
	pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;

	/// Image is NX compatible
	pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;

	/// Image understands isolation and doesn't want it
	pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;

	/// Image does not use SEH. No SE handler may reside in this image
	pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;

	/// Do not bind this image.
	pub const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;

	/// Image should execute in an AppContainer
	pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;

	/// Driver uses WDM model
	pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;

	/// Reserved.
	pub const IMAGE_DLLCHARACTERISTICS_RESERVED: u16 = 0x4000;

	/// Image is Terminal Server aware.
	pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;
}

//------------------------------------------------------------------
//
//              ENUMS
//
//------------------------------------------------------------------

/// machine type
pub enum ImageFileMachine {
	/// machine type
	Unknown = 0,

	/// Intel 386
	I386 = 0x014c,

	/// MIPS little-endian, 0x160 big-endian
	R3000 = 0x0162,

	/// MIPS little-endian
	R4000 = 0x0166,

	/// MIPS little-endian
	R10000 = 0x0168,

	/// MIPS little-endian WCE v2
	WceMipsV2 = 0x0169,

	/// Alpha_AXP
	Alpha = 0x0184,

	/// SH3 little-endian
	Sh3 = 0x01a2,

	Sh3Dsp = 0x01a3,

	/// SH3E little-endian
	Sh3E = 0x01a4,

	/// SH4 little-endian
	Sh4 = 0x01a6,

	Sh5 = 0x01a8,

	/// ARM Little-Endian
	Arm = 0x01c0,

	/// ARM Thumb/Thumb-2 Little-Endian
	Thumb = 0x01c2,

	/// ARM Thumb-2 Little-Endian
	ArmNt = 0x01c4,

	Am33 = 0x01d3,

	/// IBM PowerPC Little-Endian
	PowerPc = 0x01f0,

	PowerPcFp = 0x01f1,

	/// Intel 64
	Ia64 = 0x0200,

	/// MIPS
	Mips16 = 0x0266,

	/// ALPHA64
	Alpha64 = 0x0284,

	/// MIPS
	MipsFpu = 0x0366,

	/// MIPS
	MipsFpu16 = 0x0466,

	// /// ALPHA64
	// Axp64 = 0x0284,
	/// Infineon
	TriCore = 0x0520,

	Cef = 0x0CEF,

	/// EFI Byte Code
	Ebc = 0x0EBC,

	/// AMD64 (K8)
	Amd64 = 0x8664,

	/// M32R little-endian
	M32R = 0x9041,

	Cee = 0xC0EE,
}


#[repr(u32)]
/// Directory Entries
pub enum ImageDirectoryEntry {
	/// Export Directory
	Export = 0,

	/// Import Directory
	Import = 1,

	/// Resource Directory
	Resource = 2,

	/// Exception Directory
	Exception = 3,

	/// Security Directory
	Security = 4,

	/// base Relocation Table
	BaseReloc = 5,

	/// Debug Directory
	Debug = 6,

	/// Architecture Specific Data
	Architecture = 7,

	/// RVA of GP
	GlobalPtr = 8,

	/// TLS Directory
	Tls = 9,

	/// Load Configuration Directory
	LoadConfig = 10,

	/// Bound Import Directory in headers
	BoundImport = 11,

	/// Import Address Table
	Iat = 12,

	/// Delay Load Import Descriptors
	DelayImport = 13,

	/// COM Runtime descriptor
	ComDescriptor = 14,
}


#[repr(u16)]
/// subsystem Values
#[derive(Debug, Copy, Clone)]
pub enum ImageSubsystem {
	/// Unknown subsystem.
	Unknown = 0,

	/// Image doesn't require a subsystem.
	Native = 1,

	/// Image runs in the Windows GUI subsystem.
	WindowsGui = 2,

	/// Image runs in the Windows character subsystem.
	WindowsCui = 3,

	/// Image runs in the OS/2 character subsystem.
	Os2Cui = 5,

	/// Image runs in the Posix character subsystem.
	PosixCui = 7,

	/// Image is a native Win9x driver.
	NativeWindows = 8,

	/// Image runs in the Windows CE subsystem.
	WindowsCeGui = 9,

	/// Image is an EFI application.
	EfiApplication = 10,

	/// Image is an EFI boot service driver.
	EfiBootServiceDriver = 11,

	/// Image is an EFI runtime driver.
	EfiRuntimeDriver = 12,

	/// Image is an EFI ROM.
	EfiRom = 13,

	/// Image is an Xbox application.
	Xbox = 14,

	/// Image is a Windows boot application.
	WindowsBootApplication = 16,
}
