#![allow(nonstandard_style)] 
// #![allow(unused)]

/// All of these types are useful in some way for parsing PE Files, most specifically DLLs
/// I could do without half of that, but i'm a completionist
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
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;    // MZ
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // PE00

pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;    // PE File is a ROM
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;   // PE32
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;   // PE32+ meaning actually not 32bit but 64bits

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;



// 
// type definitions for 64-bits address space
// 
#[cfg(target_pointer_width = "64")]
pub type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
#[cfg(target_pointer_width = "64")]
pub type IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER64;
#[cfg(target_pointer_width = "64")]
pub type PIMAGE_OPTIONAL_HEADER = *mut IMAGE_OPTIONAL_HEADER64;
#[cfg(target_pointer_width = "64")]
pub const IMAGE_NT_OPTIONAL_HDR_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;

// 
// type definitions for 32-bits address space
// 
#[cfg(not(target_pointer_width = "64"))]
pub type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;
#[cfg(not(target_pointer_width = "64"))]
pub type IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER32;
#[cfg(not(target_pointer_width = "64"))]
pub type PIMAGE_OPTIONAL_HEADER = *mut IMAGE_OPTIONAL_HEADER32;

#[cfg(not(target_pointer_width = "64"))]
pub const IMAGE_NT_OPTIONAL_HDR_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
// Same stuff could be done using usize / isize, but I'm too lazy to care


//------------------------------------------------------------------
// 
//              BITFLAGS
//
//  My best shot at implementing C-Style bitflags in native rust
//  I Haven't done any methods or macro to handle the logic yet
//------------------------------------------------------------------
/// Characteristics of the image
pub mod ImageFileCharacteristics {
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


 /// DllCharacteristics Entries
 pub mod ImageDllCharacteristics {
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

/// Machine type
pub enum ImageFileMachine {
    /// Machine type
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


#[repr(u32)] /// Directory Entries
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

    /// Base Relocation Table
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


#[repr(u16)] /// Subsystem Values
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


//------------------------------------------------------------------
//
//              PE File headers
//
//------------------------------------------------------------------

///
/// DOS HEADER
///
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,       // Magic number
    pub e_cblp: u16,        // Bytes on last page of file
    pub e_cp: u16,          // Pages in file
    pub e_crlc: u16,        // Relocations
    pub e_cparhdr: u16,     // Size of header in paragraphs
    pub e_minalloc: u16,    // Minimum extra paragraphs needed
    pub e_maxalloc: u16,    // Maximum extra paragraphs needed
    pub e_ss: u16,          // Initial (relative) SS value
    pub e_sp: u16,          // Initial SP value
    pub e_csum: u16,        // Checksum
    pub e_ip: u16,          // Initial IP value
    pub e_cs: u16,          // Initial (relative) CS value
    pub e_lfarlc: u16,      // File address of relocation table
    pub e_ovno: u16,        // Overlay number
    pub e_res: [u16; 4],    // Reserved words
    pub e_oemid: u16,       // OEM identifier
    pub e_oeminfo: u16,     // OEM information
    pub e_res2: [u16; 10],  // Reserved words
    pub e_lfanew: u32,      // File address of new exe header
}


//
// 64-bits architecture specific structures for PE Files
//

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: ImageSubsystem,                   // u16
    pub DllCharacteristics: u16, // ImageDllCharacteristics
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}


//
// 32-bits architecture specific structures for PE Files
//

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: ImageSubsystem,                   // u16
    pub DllCharacteristics: u16, // ImageDllCharacteristics - 4 Bytes bitflag - Refer to the corresponding module for more information
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

//
//  OTHER GENERAL STRUCTURES FOR PE FILES 
//
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,  // ImageFileCharacteristics - 4 Bytes Bit flags - Refer to the corresponding module for more information
}



#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}



/// This structure describes the export information for a Dynamic Link Library (DLL).
/// It is used to provide information about the exported functions and their addresses.
///
/// All "AddressOf" fields are RVA, Relative Virtual Addresses
/// They are offsets, in bytes, from the base address of the DLL.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

