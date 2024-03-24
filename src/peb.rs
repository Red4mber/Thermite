#![allow(nonstandard_style)]
#![allow(dead_code)]
#![allow(unused)]

// PURE UNADULTERATED SUFFERING AHEAD

// Most of these structs were dumped using WinDbg on Win11 22H2
// Nothing has been really confirmed
// Offset errors regularly happen, expect that it will

use std::fmt;
use std::ffi::c_void;
// use std::fmt::Write;
use std::mem::size_of;      // For Tests

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

/*
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDR_MODULE {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub FlagGroup: [u8; 4],
    pub ObsoleteLoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: u32
}
*/


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _IN_PROGRESS_LINKS {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: _IN_PROGRESS_LINKS,
    pub DllBase: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub FlagGroup: [u8; 4],
    pub ObsoleteLoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: u32,
    pub EntryPointActivationContext: *mut ACTIVATION_CONTEXT,
    pub Lock: *mut c_void,
    pub DdagNode: *mut LDR_DDAG_NODE,
    pub NodeModuleLink: LIST_ENTRY,
    pub LoadContext: *mut LDRP_LOAD_CONTEXT,
    pub ParentDllBase: *mut c_void,
    pub SwitchBackContext: *mut c_void,
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
    pub ActivePatchImageBase: *mut c_void,
    pub HotPatchState: LDR_HOT_PATCH_STATE,
}
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
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RTL_BALANCED_NODE {
    pub Children: [*mut RTL_BALANCED_NODE; 2],
    // This one may be wrong, i don't really give a shit
    // Dammit i hate C unions in Rust FFI
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
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDRP_LOAD_CONTEXT {}
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
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDR_SERVICE_TAG_RECORD {
    pub Next: *mut LDR_SERVICE_TAG_RECORD,
    pub ServiceTag: *mut u32,

}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LDRP_CSLIST {
    pub Tail: *mut SINGLE_LIST_ENTRY,
}
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
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SINGLE_LIST_ENTRY {
    pub Next: *mut SINGLE_LIST_ENTRY,
}



/// Contains information filled by loader in the PEB
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u32,
    pub SsHandle: *mut c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY
}

///
/// Structure containing all User-Mode parameters associated by system with current process.
///
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Padding0: [u8; 4],
    pub Mutant: *mut c_void,
    pub ImageBaseAddress: *mut c_void,
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: *mut c_void,
    pub ProcessHeap: *mut c_void,
    pub FastPebLock: *mut c_void,
    pub AtlThunkSListPtr: *mut c_void,
    pub IFEOKey: *mut c_void,
    pub CrossProcessFlags: u32,
    pub Padding1: [u8; 4],
    pub _KernelCallbackTable: _KernelCallbackTable,
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: *mut c_void,
    pub TlsExpansionCounter: u32,
    pub Padding2: [u8; 4],
    pub TlsBitmap: *mut c_void,
    pub TlsBitmapBits: [u32; 2],
    pub ReadOnlySharedMemoryBase: *mut c_void,
    pub SharedData: *mut c_void,
    pub ReadOnlyStaticServerData: *mut *mut c_void,
    pub AnsiCodePageData: *mut c_void,
    pub OemCodePageData: *mut c_void,
    pub UnicodeCaseTableData: *mut c_void,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub CriticalSectionTimeout: i64, // LARGE_INTEGER,
    pub HeapSegmentReserve: u64,
    pub HeapSegmentCommit: u64,
    pub HeapDeCommitTotalFreeThreshold: u64,
    pub HeapDeCommitFreeBlockThreshold: u64,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: *mut *mut c_void,
    pub GdiSharedHandleTable: *mut c_void,
    pub ProcessStarterHelper: *mut c_void,
    pub GdiDCAttributeList: u32,
    pub Padding3: [u8; 4],
    pub LoaderLock: *mut c_void,
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
    pub TlsExpansionBitmap: *mut c_void,
    pub TlsExpansionBitmapBits: [u32; 32],
    pub SessionId: u32,
    pub Padding5: [u8; 4],
    pub AppCompatFlags: u64, // ULARGE_INTEGER,
    pub AppCompatFlagsUser: u64, // ULARGE_INTEGER,
    pub pShimData: *mut c_void,
    pub AppCompatInfo: *mut c_void,
    pub CSDVersion: UNICODE_STRING,
    pub ActivationContextData: *mut c_void,
    pub ProcessAssemblyStorageMap: *mut c_void,
    pub SystemDefaultActivationContextData: *mut c_void,
    pub SystemAssemblyStorageMap: *mut c_void,
    pub MinimumStackCommit: u64,
    pub SparePointers: [*mut c_void; 2],
    pub PatchLoaderData: *mut c_void,
    pub ChpeV2ProcessInfo: *mut c_void,
    pub AppModelFeatureState: u32,
    pub SpareUlongs: [u32; 2],
    pub ActiveCodePage: u16,
    pub OemCodePage: u16,
    pub UseCaseMapping: u16,
    pub UnusedNlsField: u16,
    pub WerRegistrationData: *mut c_void,
    pub WerShipAssertPtr: *mut c_void,
    pub EcCodeBitMap: *mut c_void,
    pub pImageHeaderHash: *mut c_void,
    pub TracingFlags: u32,
    pub Padding6: [u8; 4],
    pub CsrServerReadOnlySharedMemoryBase: u64,
    pub TppWorkerpListLock: u64,
    pub TppWorkerpList: LIST_ENTRY,
    pub WaitOnAddressHashTable: [*mut c_void; 128],
    pub TelemetryCoverageHeader: *mut c_void,
    pub CloudFileFlags: u32,
    pub CloudFileDiagFlags: u32,
    pub PlaceholderCompatibilityMode: u8,
    pub PlaceholderCompatibilityModeReserved: [u8; 7],
    pub LeapSecondData: *mut c_void,
    pub LeapSecondFlags: u32,
    pub NtGlobalFlag2: u32,
    pub ExtendedFeatureDisableMask: u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union _KernelCallbackTable {
    pub KernelCallbackTable: *mut c_void,
    pub UserSharedInfoPtr: *mut c_void,
}
impl std::fmt::Debug for _KernelCallbackTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            f.debug_set()
                .entry(&self.KernelCallbackTable)
                .entry(&self.UserSharedInfoPtr)
                .finish()
        }
    }
}




#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: *mut c_void,
    pub ConsoleFlags: u32,
    pub StandardInput: *mut c_void,
    pub StandardOutput: *mut c_void,
    pub StandardError: *mut c_void,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: *mut c_void,
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
    pub PackageDependencyData: *mut c_void,
    pub ProcessGroupId: u32,
    pub LoaderThreads: u32,
    pub RedirectionDllName: UNICODE_STRING,
    pub HeapPartitionName: UNICODE_STRING,
    pub DefaultThreadpoolCpuSetMasks: *mut u64,
    pub DefaultThreadpoolCpuSetMaskCount: u32,
    pub DefaultThreadpoolThreadMaximum: u32,
    pub HeapMemoryTypeMask: u32,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: u16,
    pub Length: u16,
    pub TimeStamp: u32,
    pub DosPath: UNICODE_STRING,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: *mut c_void,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}
impl fmt::Display for UNICODE_STRING {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // There's a borrow error in here according to clippy
        // But it still compiles and it still works fine...
        let buffer = unsafe {
            std::slice::from_raw_parts(
                (&self).Buffer as *const _,
                (&self.Length / 2u16) as usize
            )
        };
        let str = String::from_utf16_lossy(buffer);
        f.write_str(&*str).unwrap_or(());
        Ok(())
    }
}
// impl std::fmt::Debug for UNICODE_STRING {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         fmt::Display::fmt(self, f)
//     }
// }

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


// We don't really need all this, but I leave it anyway, just in case

// #[repr(C)]
// #[derive(Debug, Copy, Clone)]
// pub struct LARGE_INTEGER {
//     low_part: u32,
//     high_part: i32,
// }
//
// #[repr(C)]
// #[derive(Debug, Copy, Clone)]
// pub struct ULARGE_INTEGER {
//     low_part: u32,
//     high_part: u32,
// }

// // // TESTS // // //

// assert_eq!(std::mem::size_of()::<LDR_DATA_TABLE_ENTRY>(), 0x134);
