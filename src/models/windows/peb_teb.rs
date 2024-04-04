use std::ffi::c_void;
use std::fmt;
use crate::models::windows::system_info::ClientId;


/// More than 500 lines of uselessness
/// I literally could have replaced it with two or three structs at most and placeholders for the rest...
/// Why do I do that to myself ?
///

//------------------------------------------------------------------
//
//              Process environment Block
//
//------------------------------------------------------------------
///
/// Structure containing all User-Mode parameters associated by system with current process.
/// The Process environment Block (PEB) is a process’s user-mode representation.
///
/// It has the highest-level knowledge of a process in kernel mode and the lowest-level in user mode.
/// The PEB is created by the kernel but is mostly operated on from user mode.
/// If a (system) process has no user-mode footprint, it has no PEB.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PEB {
	pub inherited_address_space: u8,
	pub read_image_file_exec_options: u8,
	pub being_debugged: u8,
	pub bit_field: u8,
	pub padding0: [u8; 4],
	pub mutant: *const c_void,
	pub image_base_address: *const c_void,
	pub ldr: *const PebLdrData,
	pub process_parameters: *const RtlUserProcessParameters,
	pub sub_system_data: *const c_void,
	pub process_heap: *const c_void,
	pub fast_peb_lock: *const c_void,
	pub atl_thunk_slist_ptr: *const c_void,
	pub ifeokey: *const c_void,
	pub cross_process_flags: u32,
	pub padding1: [u8; 4],
	pub _kernel_callback_table: *const c_void,
	pub system_reserved: u32,
	pub atl_thunk_slist_ptr32: u32,
	pub api_set_map: *const c_void,
	pub tls_expansion_counter: u32,
	pub padding2: [u8; 4],
	pub tls_bitmap: *const c_void,
	pub tls_bitmap_bits: [u32; 2],
	pub read_only_shared_memory_base: *const c_void,
	pub shared_data: *const c_void,
	pub read_only_static_server_data: *const *const c_void,
	pub ansi_code_page_data: *const c_void,
	pub oem_code_page_data: *const c_void,
	pub unicode_case_table_data: *const c_void,
	pub number_of_processors: u32,
	pub nt_global_flag: u32,
	pub critical_section_timeout: i64,
	pub heap_segment_reserve: u64,
	pub heap_segment_commit: u64,
	pub heap_de_commit_total_free_threshold: u64,
	pub heap_de_commit_free_block_threshold: u64,
	pub number_of_heaps: u32,
	pub maximum_number_of_heaps: u32,
	pub process_heaps: *const *const c_void,
	pub gdi_shared_handle_table: *const c_void,
	pub process_starter_helper: *const c_void,
	pub gdi_dcattribute_list: u32,
	pub padding3: [u8; 4],
	pub loader_lock: *const c_void,
	pub osmajor_version: u32,
	pub osminor_version: u32,
	pub osbuild_number: u16,
	pub oscsdversion: u16,
	pub osplatform_id: u32,
	pub image_subsystem: u32,
	pub image_subsystem_major_version: u32,
	pub image_subsystem_minor_version: u32,
	pub padding4: [u8; 4],
	pub active_process_affinity_mask: u64,
	pub gdi_handle_buffer: [u32; 60],
	pub post_process_init_routine: extern "system" fn(),
	pub tls_expansion_bitmap: *const c_void,
	pub tls_expansion_bitmap_bits: [u32; 32],
	pub session_id: u32,
	pub padding5: [u8; 4],
	pub app_compat_flags: u64,
	pub app_compat_flags_user: u64,
	pub p_shim_data: *const c_void,
	pub app_compat_info: *const c_void,
	pub csdversion: UnicodeString,
	pub activation_context_data: *const c_void,
	pub process_assembly_storage_map: *const c_void,
	pub system_default_activation_context_data: *const c_void,
	pub system_assembly_storage_map: *const c_void,
	pub minimum_stack_commit: u64,
	pub spare_pointers: [*const c_void; 2],
	pub patch_loader_data: *const c_void,
	pub chpe_v2process_info: *const c_void,
	pub app_model_feature_state: u32,
	pub spare_ulongs: [u32; 2],
	pub active_code_page: u16,
	pub oem_code_page: u16,
	pub use_case_mapping: u16,
	pub unused_nls_field: u16,
	pub wer_registration_data: *const c_void,
	pub wer_ship_assert_ptr: *const c_void,
	pub ec_code_bit_map: *const c_void,
	pub p_image_header_hash: *const c_void,
	pub tracing_flags: u32,
	pub padding6: [u8; 4],
	pub csr_server_read_only_shared_memory_base: u64,
	pub tpp_workerp_list_lock: u64,
	pub tpp_workerp_list: ListEntry,
	pub wait_on_address_hash_table: [*const c_void; 128],
	pub telemetry_coverage_header: *const c_void,
	pub cloud_file_flags: u32,
	pub cloud_file_diag_flags: u32,
	pub placeholder_compatibility_mode: u8,
	pub placeholder_compatibility_mode_reserved: [u8; 7],
	pub leap_second_data: *const c_void,
	pub leap_second_flags: u32,
	pub nt_global_flag2: u32,
	pub extended_feature_disable_mask: u64,
}


///
/// The PebLdrData structure is the defining record of which user-mode modules are loaded in a process.
///
/// It is essentially the head of three double-linked lists of [LdrDataTableEntry] structures.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PebLdrData {
	pub length: u32,
	pub initialized: u32,
	pub ss_handle: *const c_void,
	pub in_load_order_module_list: ListEntry,
	pub in_memory_order_module_list: ListEntry,
	pub in_initialization_order_module_list: ListEntry,
}


/// An entry in a doubly-linked list.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ListEntry {
	/// Forward Link
	pub flink: *const ListEntry,

	/// Backwards Link
	pub blink: *const ListEntry,
}


/// An entry in a single-linked list
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SingleListEntry {
	pub next: *const SingleListEntry,
}


/// The LdrDataTableEntry structure is the record of how a DLL is loaded into a process.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LdrDataTableEntry {
	pub in_load_order_links: ListEntry,
	pub in_memory_order_links: ListEntry,
	pub in_initialization_order_links: ListEntry,
	pub dll_base: *const c_void,
	pub entry_point: *const c_void,
	pub size_of_image: u32,
	pub full_dll_name: UnicodeString,
	pub base_dll_name: UnicodeString,
	pub flag_group: [u8; 4],
	pub obsolete_load_count: u16,
	pub tls_index: u16,
	pub hash_links: ListEntry,
	pub time_date_stamp: u32,
	pub entry_point_activation_context: *const ActivationContext,
	pub lock: *const c_void,
	pub ddag_node: *const LdrDdagNode,
	pub node_module_link: ListEntry,
	pub load_context: *const LdrpLoadContext,
	pub parent_dll_base: *const c_void,
	pub switch_back_context: *const c_void,
	pub base_address_index_node: RtlBalancedNode,
	pub mapping_info_index_node: RtlBalancedNode,
	pub original_base: u64,
	pub load_time: i64,
	pub base_name_hash_value: u32,
	pub load_reason: LdrDllLoadReason,
	pub implicit_path_options: u32,
	pub reference_count: u32,
	pub dependent_load_flags: u32,
	pub signing_level: u8,
	pub check_sum: u32,
	pub active_patch_image_base: *const c_void,
	pub hot_patch_state: LdrHotPatchState,
}


// The implementation is still a bit fucked up,
// IDK how to properly port C-Style unions in rust
#[repr(C)]
#[derive(Copy, Clone)]
pub union _KernelCallbackTable {
	pub kernel_callback_table: *const c_void,
	pub user_shared_info_ptr: *const c_void,
}


// I hate to write this because
// Debug can't be derived from unions x_X
impl fmt::Debug for _KernelCallbackTable {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		unsafe {
			f.debug_set()
				.entry(&self.kernel_callback_table)
				.entry(&self.user_shared_info_ptr)
			 .finish()
		}
	}
}

//
// DLL LOADER ENUMS and Types
//
/////////////////////////////////////////

/// state of the module loader
/// Only in LdrDataTableEntry
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LdrDdagState {
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


/// Self-Explanatory
/// Reason why the DLL is loaded
/// Only found in LdrDataTableEntry.
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LdrDllLoadReason {
	StaticDependency = 0,
	StaticForwarderDependency = 1,
	DynamicForwarderDependency = 2,
	DelayloadDependency = 3,
	DynamicLoad = 4,
	AsImageLoad = 5,
	AsDataLoad = 6,
	EnclavePrimary = 7,
	EnclaveDependency = 8,
	PatchImage = 9,
	Unknown = -1,
}


// I genuinely have no idea what it's for
#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LdrHotPatchState {
	BaseImage,
	NotApplied,
	AppliedReverse,
	AppliedForward,
	FailedToPatch,
	StateMax,
}


///
/// Extends the LdrDataTableEntry that represents a loaded module.
///
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LdrDdagNode {
	pub modules: ListEntry,
	pub service_tag_list: *const LdrServiceTagRecord,
	pub load_count: u32,
	pub load_while_unloading_count: u32,
	pub lowest_link: u32,
	pub dependencies: LdrpCslist,
	pub incoming_dependencies: LdrpCslist,
	pub state: LdrDdagState,
	pub condense_link: SingleListEntry,
	pub preorder_number: u32,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LdrServiceTagRecord {
	pub next: *const LdrServiceTagRecord,
	pub service_tag: *const u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LdrpCslist {
	pub tail: *const SingleListEntry,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LdrpLoadContext {}


//=====================================================
//
//      Thread Environment Block
//
// > Fully loaded
// No missing field, including undocumented ones
// All sizes and offsets verified (and corrected)
//=====================================================
#[repr(C)]
#[derive(Debug)]
pub struct TEB {
	pub nt_tib: NtTib,
	pub environment_pointer: *const c_void,
	pub client_id: ClientId,
	pub active_rpc_handle: *const c_void,
	pub thread_local_storage_pointer: *const c_void,
	pub process_environment_block: *const PEB,
	pub last_error_value: u32,
	pub count_of_owned_critical_sections: u32,
	pub csr_client_thread: *const c_void,
	pub win32thread_info: *const c_void,
	pub user32reserved: [u32; 26],
	pub user_reserved: [u32; 5],
	pub wow32reserved: *const c_void,
	pub current_locale: u32,
	pub fp_software_status_register: u32,
	pub reserved_for_debugger_instrumentation: [*const c_void; 16],
	pub system_reserved1: [*const c_void; 30],
	pub placeholder_compatibility_mode: u8,
	pub placeholder_hydration_always_explicit: u8,
	pub placeholder_reserved: [u8; 10],
	pub proxied_process_id: u32,
	pub _activation_stack: ActivationContextStack,
	pub working_on_behalf_ticket: [u8; 8],
	pub exception_code: i32,
	pub padding0: [u8; 4],
	pub activation_context_stack_pointer: *const ActivationContextStack,
	pub instrumentation_callback_sp: u64,
	pub instrumentation_callback_previous_pc: u64,
	pub instrumentation_callback_previous_sp: u64,
	pub tx_fs_context: u32,
	pub instrumentation_callback_disabled: u8,
	pub unaligned_load_store_exceptions: u8,
	pub padding1: [u8; 2],
	pub gdi_teb_batch: GdiTebBatch,
	pub real_client_id: ClientId,
	pub gdi_cached_process_handle: *const c_void,
	pub gdi_client_pid: u32,
	pub gdi_client_tid: u32,
	pub gdi_thread_local_info: *const c_void,
	pub win32client_info: [u64; 62],
	pub gl_dispatch_table: [*const c_void; 233],
	pub gl_reserved1: [u64; 29],
	pub gl_reserved2: *const c_void,
	pub gl_section_info: *const c_void,
	pub gl_section: *const c_void,
	pub gl_table: *const c_void,
	pub gl_current_rc: *const c_void,
	pub gl_context: *const c_void,
	pub last_status_value: u32,
	pub padding2: [u8; 4],
	pub static_unicode_string: UnicodeString,
	pub static_unicode_buffer: [u16; 261],
	pub padding3: [u8; 6],
	pub deallocation_stack: *const c_void,
	pub tls_slots: [*const c_void; 64],
	pub tls_links: ListEntry,
	pub vdm: *const c_void,
	pub reserved_for_nt_rpc: *const c_void,
	pub dbg_ss_reserved: [*const c_void; 2],
	pub hard_error_mode: u32,
	pub padding4: [u8; 4],
	pub instrumentation: [*const c_void; 11],
	pub activity_id: Guid,
	pub sub_process_tag: *const c_void,
	pub perflib_data: *const c_void,
	pub etw_trace_data: *const c_void,
	pub win_sock_data: *const c_void,
	pub gdi_batch_count: u32,
	pub current_ideal_processor: IdealProcessorUnion,
	pub guaranteed_stack_bytes: u32,
	pub padding5: [u8; 4],
	pub reserved_for_perf: *const c_void,
	pub reserved_for_ole: *const c_void,
	pub waiting_on_loader_lock: u32,
	pub padding6: [u8; 4],
	pub saved_priority_state: *const c_void,
	pub reserved_for_code_coverage: u64,
	pub thread_pool_data: *const c_void,
	pub tls_expansion_slots: *const *const c_void,
	pub chpe_v2cpu_area_info: *const Chpev2CpuareaInfo,
	pub unused: *const c_void,
	pub mui_generation: u32,
	pub is_impersonating: u32,
	pub nls_cache: *const c_void,
	pub p_shim_data: *const c_void,
	pub heap_data: u32,
	pub padding7: [u8; 4],
	pub current_transaction_handle: *const c_void,
	pub active_frame: *const TEBActiveFrame,
	pub fls_data: *const c_void,
	pub preferred_languages: *const c_void,
	pub user_pref_languages: *const c_void,
	pub merged_pref_languages: *const c_void,
	pub mui_impersonation: u32,
	pub teb_flags: TebFlagsUnion,
	pub txn_scope_enter_callback: *const c_void,
	pub txn_scope_exit_callback: *const c_void,
	pub txn_scope_context: *const c_void,
	pub lock_count: u32,
	pub wow_teb_offset: i32,
	pub resource_ret_value: *const c_void,
	pub reserved_for_wdf: *const c_void,
	pub reserved_for_crt: u64,
	pub effective_container_id: Guid,
	pub last_sleep_counter: u64,
	pub spin_call_count: u32,
	pub padding8: [u8; 4],
	pub extended_feature_disable_mask: u64,
}

#[repr(C)]
pub struct TEBActiveFrame {
	pub flags: u64,
	pub previous: *const TEBActiveFrame,
	pub context: *const TEBActiveFrameContext,
}


#[repr(C)]
pub struct TEBActiveFrameContext {
	pub flags: u64,
	pub frame_name: *const u8,
}


#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProcessorNumber {
	pub group: u16,
	pub number: u8,
	pub reserved: u8,
}


#[repr(C)]
pub union IdealProcessorUnion {
	pub current_ideal_processor: ProcessorNumber,
	pub reserved_pad_0: u8,
	pub reserved_pad_1: u8,
	pub reserved_pad_2: u8,
	pub ideal_processor: u8,
}


impl fmt::Debug for IdealProcessorUnion {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		unsafe {
			f.debug_set()
			 .entry(&self.current_ideal_processor)
			 .entry(&self.ideal_processor)
			 .finish()
		}
	}
}
pub union TebFlagsUnion {
	pub cross_teb_flags: u16,
	// - SpareCrossTebBits : Pos 0, 16 Bits,
	pub same_teb_flags: u16,
	// - SafeThunkCall    : Pos 0, 1 Bit,
	// - InDebugPrint     : Pos 1, 1 Bit,
	// - HasFiberData     : Pos 2, 1 Bit,
	// - SkipThreadAttach : Pos 3, 1 Bit,
	// - WerInShipAssertCode : Pos 4, 1 Bit,
	// - RanProcessInit   : Pos 5, 1 Bit,
	// - ClonedThread     : Pos 6, 1 Bit,
	// - SuppressDebugMsg : Pos 7, 1 Bit,
	// - DisableUserStackWalk : Pos 8, 1 Bit,
	// - RtlExceptionAttached : Pos 9, 1 Bit,
	// - InitialThread    : Pos 10, 1 Bit,
	// - SessionAware     : Pos 11, 1 Bit,
	// - LoadOwner        : Pos 12, 1 Bit,
	// - LoaderWorker     : Pos 13, 1 Bit,
	// - SkipLoaderInit   : Pos 14, 1 Bit,
	// - SkipFileAPIBrokering : Pos 15, 1 Bit,
}


impl fmt::Debug for TebFlagsUnion {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		unsafe {
			f.debug_set()
			 .entry(&self.cross_teb_flags)
			 .entry(&self.same_teb_flags)
			 .finish()
		}
	}
}


#[repr(C)]
#[derive(Debug)]
pub struct ActivationContextStack {
	pub active_frame: *const RtlActivationContextStackFrame,
	pub frame_list_cache: ListEntry,
	pub flags: u32,
	pub next_cookie_sequence_number: u32,
	pub stack_id: u32,
}


#[repr(C)]
#[derive(Debug)]
pub struct RtlActivationContextStackFrame {
	pub previous: *const RtlActivationContextStackFrame,
	pub context: *const ActivationContext,
	pub flags: u64,
}


#[repr(C)]
#[derive(Debug)]
pub struct GdiTebBatch {
	pub has_rendering_command: u32,
	pub hdc: u64,
	pub buffer: [u32; 310],
}


#[repr(C)]
#[derive(Debug)]
pub struct NtTib {
	pub exception_list: *const ExceptionRegistrationRecord,
	pub stack_base: *const c_void,
	pub stack_limit: *const c_void,
	pub sub_system_tib: *const c_void,
	pub fiber_data: FiberDataUnion,
	pub arbitrary_user_pointer: *const c_void,
	pub self_ptr: *const NtTib,
}


#[repr(C)]
#[derive(Debug)]
pub struct ExceptionRegistrationRecord {
	pub next: *const ExceptionRegistrationRecord,
	pub handler: *const ExceptionDisposition,
}


#[repr(C)]
pub union FiberDataUnion {
	pub fiber_data: *const c_void,
	pub version: u32,
}


impl fmt::Debug for FiberDataUnion {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		unsafe {
			f.debug_set()
			 .entry(&self.fiber_data)
			 .entry(&self.version)
			 .finish()
		}
	}
}

#[repr(u32)]
#[derive(Debug)]
pub enum ExceptionDisposition {
	ExceptionContinueExecution = 0,
	ExceptionContinueSearch = 1,
	ExceptionNestedException = 2,
	ExceptionCollidedUnwind = 3,
}


pub struct Chpev2CpuareaInfo;

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
pub struct RtlUserProcessParameters {
	pub maximum_length: u32,
	pub length: u32,
	pub flags: u32,
	pub debug_flags: u32,
	pub console_handle: *const c_void,
	pub console_flags: u32,
	pub standard_input: *const c_void,
	pub standard_output: *const c_void,
	pub standard_error: *const c_void,
	pub current_directory: CURDIR,
	pub dll_path: UnicodeString,
	pub image_path_name: UnicodeString,
	pub command_line: UnicodeString,
	pub environment: *const c_void,
	pub starting_x: u32,
	pub starting_y: u32,
	pub count_x: u32,
	pub count_y: u32,
	pub count_chars_x: u32,
	pub count_chars_y: u32,
	pub fill_attribute: u32,
	pub window_flags: u32,
	pub show_window_flags: u32,
	pub window_title: UnicodeString,
	pub desktop_info: UnicodeString,
	pub shell_info: UnicodeString,
	pub runtime_data: UnicodeString,
	pub current_directories: [RtlDriveLetterCurdir; 32],
	pub environment_size: u64,
	pub environment_version: u64,
	pub package_dependency_data: *const c_void,
	pub process_group_id: u32,
	pub loader_threads: u32,
	pub redirection_dll_name: UnicodeString,
	pub heap_partition_name: UnicodeString,
	pub default_threadpool_cpu_set_masks: *const u64,
	pub default_threadpool_cpu_set_mask_count: u32,
	pub default_threadpool_thread_maximum: u32,
	pub heap_memory_type_mask: u32,
}


/// From Geoff Chappell:
///
/// "small structure that is presently thought to be
///  defined in all Windows versions but not used in any."
///
///  Peak Microsoft
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RtlDriveLetterCurdir {
	pub flags: u16,
	pub length: u16,
	pub time_stamp: u32,
	pub dos_path: UnicodeString,
}


/// Designed to be nested within another structure to allow
/// the other structure can be the node of a binary search tree
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RtlBalancedNode {
	pub children: [*const RtlBalancedNode; 2],
	pub parent_value: u64,
}


impl RtlBalancedNode {
	#[inline]
	pub fn left(&self) -> *const RtlBalancedNode {
		self.children[0]
	}
	#[inline]
	pub fn right(&self) -> *const RtlBalancedNode {
		self.children[1]
	}
}

//------------------------------------------------------------------
//
//              Other useful data types
//    I implemented some Traits to do incredible stuff
//      like casting a string as a string
//
//------------------------------------------------------------------

///
///
///
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CURDIR {
	pub dos_path: UnicodeString,
	pub handle: *const c_void,
}


///
///
///
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ActivationContext {
	pub modules: ListEntry,
	pub service_tag_list: *const LdrServiceTagRecord,
	pub load_count: u32,
	pub load_while_unloading_count: u32,
	pub lowest_link: u32,
	pub dependencies: LdrpCslist,
	pub incoming_dependencies: LdrpCslist,
	pub state: LdrDdagState,
	pub condense_link: SingleListEntry,
	pub preorder_number: u32,
}


#[repr(C)]
#[derive(Copy, Clone)]
pub struct UnicodeString {
	pub length: u16,
	pub maximum_length: u16,
	pub buffer: *const u16,
}


// I swear, I'm going to put a head sized hole in my desk if I ever have
// to implement fmt::Display and Debug for a string ever again
impl fmt::Display for UnicodeString {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let buffer = unsafe {
			std::slice::from_raw_parts(
				(&self).buffer as *const _,
				std::cmp::min((&self.length / 2u16) as usize, 150),
			)
		};
		let str = String::from_utf16_lossy(buffer);
		f.write_str(&*str).unwrap_or(());
		Ok(())
	}
}


impl fmt::Debug for UnicodeString {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}


#[repr(C)]
pub struct Guid {
	pub data1: u32,
	pub data2: u16,
	pub data3: u16,
	pub data4: [u8; 8],
}


impl fmt::Debug for Guid {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{:08X?}-{:04X?}-{:04X?}-{:02X?}{:02X?}-{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}", self.data1, self.data2, self.data3, self.data4[0], self.data4[1], self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7])
	}
}

// Why tf did i even bother make a large integer type when there's u64 and i64 ?!
// Damn sometimes i really need to turn my brain on before coding

// //
// // Signed 64-bits integer
// // Can simply be replaced by a simple u64
// #[repr(C)]
// #[derive(Copy, Clone)]
// pub struct LARGE_INTEGER {
//     low_part: u32,
//     high_part: i32,
// }
//
// impl fmt::Display for LARGE_INTEGER {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let high = self.high_part.clone() as i64;
//         let low = self.low_part.clone() as u64;
//         write!(f, "{}", (high << 32) | low as i64)
//     }
// }
// impl fmt::Debug for LARGE_INTEGER {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         fmt::Display::fmt(self, f)
//     }
// }

// //
// // Unsigned 64bit integer
// // Can simply be replaced by a simple u64
// #[repr(C)]
// #[derive(Copy, Clone)]
// pub struct ULARGE_INTEGER {
//     low_part: u32,
//     high_part: u32,
// }
//
// impl fmt::Display for ULARGE_INTEGER {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let high = self.high_part.clone() as u64;
//         let low = self.low_part.clone() as u64;
//         write!(f, "{}", (high << 32) | low)
//     }
// }
//
// impl fmt::Debug for ULARGE_INTEGER {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         fmt::Display::fmt(self, f)
//     }
// }
