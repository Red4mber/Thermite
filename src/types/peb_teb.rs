#![allow(nonstandard_style)]
#![allow(unused)]

///////////////////////////////////////////////////////////
//
//        == Windows Internals Rust Types ==
//        -- Miscellaneous Windows Internals --
//
//              Like the PEB and stuff 
//        Feel free to steal it, it works okay-ish 
//
//          Made by RedAmber - 26 March 2024
///////////////////////////////////////////////////////////

use std::ffi::c_void;
use std::fmt;


//------------------------------------------------------------------
//
//              Process Environment Block
//
//------------------------------------------------------------------
///
/// Structure containing all User-Mode parameters associated by system with current process.
/// The Process Environment Block (PEB) is a process’s user-mode representation. 
/// 
/// It has the highest-level knowledge of a process in kernel mode and the lowest-level in user mode. 
/// The PEB is created by the kernel but is mostly operated on from user mode. 
/// If a (system) process has no user-mode footprint, it has no PEB.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Padding0: [u8; 4],
    pub Mutant: *const c_void,
    pub ImageBaseAddress: *const c_void,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: *const c_void,
    pub ProcessHeap: *const c_void,
    pub FastPebLock: *const c_void, // _RTL_CRITICAL_SECTION NYI
    pub AtlThunkSListPtr: *const c_void, // _SLIST_HEADER NYI
    pub IFEOKey: *const c_void,
    pub CrossProcessFlags: u32, // Bitfield here
    pub Padding1: [u8; 4],
    pub _KernelCallbackTable: *const c_void, // I may have missed a union, but screw that
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: *const c_void,
    pub TlsExpansionCounter: u32,
    pub Padding2: [u8; 4],
    pub TlsBitmap: *const c_void, // _RTL_BITMAP NYI
    pub TlsBitmapBits: [u32; 2],
    pub ReadOnlySharedMemoryBase: *const c_void,
    pub SharedData: *const c_void,
    pub ReadOnlyStaticServerData: *mut *const c_void,
    pub AnsiCodePageData: *const c_void,
    pub OemCodePageData: *const c_void,
    pub UnicodeCaseTableData: *const c_void,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub CriticalSectionTimeout: LARGE_INTEGER,
    pub HeapSegmentReserve: u64,
    pub HeapSegmentCommit: u64,
    pub HeapDeCommitTotalFreeThreshold: u64,
    pub HeapDeCommitFreeBlockThreshold: u64,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: *mut *const c_void,
    pub GdiSharedHandleTable: *const c_void,
    pub ProcessStarterHelper: *const c_void,
    pub GdiDCAttributeList: u32,
    pub Padding3: [u8; 4],
    pub LoaderLock: *const c_void, // _RTL_CRITICAL_SECTION NYI
    pub OSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u16,
    pub OSCSDVersion: u16,
    pub OSPlatformId: u32,
    pub ImageSubsystem: u32,
    pub ImageSubsystemMajorVersion: u32,
    pub ImageSubsystemMinorVersion: u32,
    pub Padding4: [u8; 4],
    pub ActiveProcessAffinityMask: u64,
    pub GdiHandleBuffer: [u32; 60],
    pub PostProcessInitRoutine: extern "system" fn(),
    pub TlsExpansionBitmap: *const c_void, // _RTL_BITMAP NYI
    pub TlsExpansionBitmapBits: [u32; 32],
    pub SessionId: u32,
    pub Padding5: [u8; 4],
    pub AppCompatFlags: ULARGE_INTEGER,
    pub AppCompatFlagsUser: ULARGE_INTEGER,
    pub pShimData: *const c_void,
    pub AppCompatInfo: *const c_void,
    pub CSDVersion: UNICODE_STRING,
    pub ActivationContextData: *const c_void, // _ACTIVATION_CONTEXT_DATA NYI
    pub ProcessAssemblyStorageMap: *const c_void, // _ASSEMBLY_STORAGE_MAP NYI
    pub SystemDefaultActivationContextData: *const c_void, // _ACTIVATION_CONTEXT_DATA NYI
    pub SystemAssemblyStorageMap: *const c_void, // _ASSEMBLY_STORAGE_MAP NYI
    pub MinimumStackCommit: u64,
    pub SparePointers: [*const c_void; 2],
    pub PatchLoaderData: *const c_void,
    pub ChpeV2ProcessInfo: *const c_void, // _CHPEV2_PROCESS_INFO NYI
    pub AppModelFeatureState: u32,
    pub SpareUlongs: [u32; 2],
    pub ActiveCodePage: u16,
    pub OemCodePage: u16,
    pub UseCaseMapping: u16,
    pub UnusedNlsField: u16,
    pub WerRegistrationData: *const c_void,
    pub WerShipAssertPtr: *const c_void,
    pub EcCodeBitMap: *const c_void,
    pub pImageHeaderHash: *const c_void,
    pub TracingFlags: u32,
    pub Padding6: [u8; 4],
    pub CsrServerReadOnlySharedMemoryBase: u64,
    pub TppWorkerpListLock: u64,
    pub TppWorkerpList: LIST_ENTRY,
    pub WaitOnAddressHashTable: [*const c_void; 128],
    pub TelemetryCoverageHeader: *const c_void,
    pub CloudFileFlags: u32,
    pub CloudFileDiagFlags: u32,
    pub PlaceholderCompatibilityMode: u8,
    pub PlaceholderCompatibilityModeReserved: [u8; 7],
    pub LeapSecondData: *const c_void,    // _LEAP_SECOND_DATA NYI
    pub LeapSecondFlags: u32,
    pub NtGlobalFlag2: u32,
    pub ExtendedFeatureDisableMask: u64,
}

///
/// The PEB_LDR_DATA structure is the defining record of which user-mode modules are loaded in a process. 
/// It is essentially the head of three double-linked lists of LDR_DATA_TABLE_ENTRY structures. 
/// Each structure represents one loaded module. Each list links through the structures in a different order. 
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u32,
    pub SsHandle: *const c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
}

/// Doubly-linked list. This structure is made to be embedded in another structure, allowing to navigate between them by following the lists links.
/// It wraps around, meaning that Blink of the first element points to the last element.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LIST_ENTRY {
    /// Forward Link
    pub Flink: *mut LIST_ENTRY,

    /// Backwards Link
    pub Blink: *mut LIST_ENTRY,
}

/// Single-linked list
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SINGLE_LIST_ENTRY {
    pub Next: *mut SINGLE_LIST_ENTRY,
}


/// The LDR_DATA_TABLE_ENTRY structure is NTDLL’s record of how a DLL is loaded into a process. 
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: *const c_void,
    pub EntryPoint: *const c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub FlagGroup: [u8; 4],
    pub ObsoleteLoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: u32,
    pub EntryPointActivationContext: *mut ACTIVATION_CONTEXT,
    pub Lock: *const c_void,
    pub DdagNode: *mut LDR_DDAG_NODE,
    pub NodeModuleLink: LIST_ENTRY,
    pub LoadContext: *mut LDRP_LOAD_CONTEXT,
    pub ParentDllBase: *const c_void,
    pub SwitchBackContext: *const c_void,
    pub BaseAddressIndexNode: RTL_BALANCED_NODE,
    pub MappingInfoIndexNode: RTL_BALANCED_NODE,
    pub OriginalBase: u64,
    pub LoadTime: i64,
    pub BaseNameHashValue: u32,
    pub LoadReason: LDR_DLL_LOAD_REASON,
    pub ImplicitPathOptions: u32,
    pub ReferenceCount: u32,
    pub DependentLoadFlags: u32,
    pub SigningLevel: u8,
    pub CheckSum: u32,
    pub ActivePatchImageBase: *const c_void,
    pub HotPatchState: LDR_HOT_PATCH_STATE,
}

// The implementation is still a bit fucked up, 
// IDK how to properly do C-Style unions in rust
#[repr(C)]
#[derive(Copy, Clone)]
pub union _KernelCallbackTable {
    pub KernelCallbackTable: *const c_void,
    pub UserSharedInfoPtr: *const c_void,
}
// I hate to write this because 
// Debug can't be derived from unions x_X
impl fmt::Debug for _KernelCallbackTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            f.debug_set()
                .entry(&self.KernelCallbackTable)
                .entry(&self.UserSharedInfoPtr)
                .finish()
        }
    }
}

//
// DLL LOADER ENUMS 
// and Types  
// 
/////////////////////////////////////////

/// State of the module loader
/// Only in LDR_DATA_TABLE_ENTRY
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LDR_DDAG_STATE {
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9,
}

/// Self explanatory
/// Reason why the DLL is loaded
/// Only found in LDR_DATA_TABLE_ENTRY. 
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LDR_DLL_LOAD_REASON {
    LoadReasonStaticDependency = 0,
    LoadReasonStaticForwarderDependency = 1,
    LoadReasonDynamicForwarderDependency = 2,
    LoadReasonDelayloadDependency = 3,
    LoadReasonDynamicLoad = 4,
    LoadReasonAsImageLoad = 5,
    LoadReasonAsDataLoad = 6,
    LoadReasonEnclavePrimary = 7,
    LoadReasonEnclaveDependency = 8,
    LoadReasonPatchImage = 9,
    LoadReasonUnknown = -1,
}


// I geniunely have no idea
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LDR_HOT_PATCH_STATE {
    LdrHotPatchBaseImage,
    LdrHotPatchNotApplied,
    LdrHotPatchAppliedReverse,
    LdrHotPatchAppliedForward,
    LdrHotPatchFailedToPatch,
    LdrHotPatchStateMax,
}

///
/// Extends the LDR_DATA_TABLE_ENTRY that represents a loaded module.
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDR_DDAG_NODE {
    pub Modules: LIST_ENTRY,
    pub ServiceTagList: *mut LDR_SERVICE_TAG_RECORD,
    pub LoadCount: u32,
    pub LoadWhileUnloadingCount: u32,
    pub LowestLink: u32,
    pub Dependencies: LDRP_CSLIST,
    pub IncomingDependencies: LDRP_CSLIST,
    pub State: LDR_DDAG_STATE,
    pub CondenseLink: SINGLE_LIST_ENTRY,
    pub PreorderNumber: u32,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDR_SERVICE_TAG_RECORD {
    pub Next: *mut LDR_SERVICE_TAG_RECORD,
    pub ServiceTag: *mut u32,

}

//
//  
//
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDRP_CSLIST {
    pub Tail: *mut SINGLE_LIST_ENTRY,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDRP_LOAD_CONTEXT {}

//============================================================================
//
//              === Run Time Libraries structures ===
// 
//
//=============================================================================


///
/// Low-level packaging of the numerous arguments and parameters
/// that can be specified to such Win32 API functions as CreateProcess 
/// for the transition to and from kernel mode. 
/// 
/// Stores the input to the RtlCreateUserProcess function.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: *const c_void,
    pub ConsoleFlags: u32,
    pub StandardInput: *const c_void,
    pub StandardOutput: *const c_void,
    pub StandardError: *const c_void,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: *const c_void,
    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,
    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; 32],
    pub EnvironmentSize: u64,
    pub EnvironmentVersion: u64,
    pub PackageDependencyData: *const c_void,
    pub ProcessGroupId: u32,
    pub LoaderThreads: u32,
    pub RedirectionDllName: UNICODE_STRING,
    pub HeapPartitionName: UNICODE_STRING,
    pub DefaultThreadpoolCpuSetMasks: *mut u64,
    pub DefaultThreadpoolCpuSetMaskCount: u32,
    pub DefaultThreadpoolThreadMaximum: u32,
    pub HeapMemoryTypeMask: u32,
}

/// From Geoff Chappell:
/// 
/// "small structure that is presently thought to be
///  defined in all Windows versions but not used in any."
/// 
///  Peak Microsoft 
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: u16,
    pub Length: u16,
    pub TimeStamp: u32,
    pub DosPath: UNICODE_STRING,
}

/// Designed to be nested within another structure to allow 
/// the other structure can be the node of a binary search tree
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RTL_BALANCED_NODE {
    pub Children: [*mut RTL_BALANCED_NODE; 2],
    pub ParentValue: u64,
}
impl RTL_BALANCED_NODE {
    #[inline]
    pub fn Left(&self) -> *mut RTL_BALANCED_NODE {
        self.Children[0]
    }
    #[inline]
    pub fn Right(&self) -> *mut RTL_BALANCED_NODE {
        self.Children[1]
    }
}

//------------------------------------------------------------------
//
//              Other useful data types
//    I implemented some Traits to do incredible stuff, 
//      like casting a string as a string
//
//------------------------------------------------------------------

///
/// 
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: *const c_void,
}

///
/// 
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ACTIVATION_CONTEXT {
    pub Modules: LIST_ENTRY,
    pub ServiceTagList: *mut LDR_SERVICE_TAG_RECORD,
    pub LoadCount: u32,
    pub LoadWhileUnloadingCount: u32,
    pub LowestLink: u32,
    pub Dependencies: LDRP_CSLIST,
    pub IncomingDependencies: LDRP_CSLIST,
    pub State: LDR_DDAG_STATE,
    pub CondenseLink: SINGLE_LIST_ENTRY,
    pub PreorderNumber: u32,
}


///
/// Ah Yes
/// A structure to define a string, we really needed that
///
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}
// Gonna put a head sized hole in my desk after having to implement fmt::Display for a string
impl fmt::Display for UNICODE_STRING {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let buffer = unsafe {
            std::slice::from_raw_parts(
                (&self).Buffer as *const _,
                std::cmp::min((&self.Length / 2u16) as usize, 150),
            )
        };
        let str = String::from_utf16_lossy(buffer);
        f.write_str(&*str).unwrap_or(());
        Ok(())
    }
}
impl fmt::Debug for UNICODE_STRING {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

//
// Signed 64-bits integer
//
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LARGE_INTEGER {
    low_part: u32,
    high_part: i32,
}

impl fmt::Display for LARGE_INTEGER {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let high = self.high_part.clone() as i64;
        let low = self.low_part.clone() as u64;
        write!(f, "{}", (high << 32) | low as i64)
    }
}
impl fmt::Debug for LARGE_INTEGER {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

//
// Unsigned 64bit integer
//
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ULARGE_INTEGER {
    low_part: u32,
    high_part: u32,
}

impl fmt::Display for ULARGE_INTEGER {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let high = self.high_part.clone() as u64;
        let low = self.low_part.clone() as u64;
        write!(f, "{}", (high << 32) | low)
    }
}

impl fmt::Debug for ULARGE_INTEGER {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}


//
// TODO 
// - Implement tests for structure size and offsets
// - Implement NYI structures