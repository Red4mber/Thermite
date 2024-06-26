use winapi::shared::ntdef::{OBJECT_ATTRIBUTES, UNICODE_STRING};


// Utility function to get an actual string from window's UNICODE_STRING
pub fn handle_unicode_string(uni: UNICODE_STRING) -> String {
	let buffer = unsafe {
		std::slice::from_raw_parts(
			uni.Buffer,
			(&uni.Length / 2u16) as usize,
		)
	};
	 String::from_utf16_lossy(buffer)
}

pub fn get_empty_objectattributes() -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as _,
        RootDirectory: 0u32 as _,
        ObjectName: 0u32 as _,
        Attributes: 0,
        SecurityDescriptor: 0u32 as _,
        SecurityQualityOfService: 0u32 as _,
    }
}




//
// Below are my own macros for debugging/logging
//
// They're not that good, they certainly aren't better than the log crate, but they're mine
// I tried to make them as similar as possible with log:: so that you wouldn't have too much code to change if you want to change


// Prints stuff, offset by one tab, to stay aligned with the nice headers
#[macro_export]
macro_rules! _debug_print {
    ($val:literal$(,)?) => {
        println!("\t{}", $val);
    };
    ($val:expr$(,)?) => {
        println!(
            "\t{} = {}",
            stringify!($val),
            format!("{:#x?}", $val)
                .replace("\n ", "\n\t-")
                .replace(['{', '}', '[', ']', ','], "")  // Also removing some clutter
                .trim()
        );
    };
}

#[macro_export] macro_rules! debug {
    () => {
        println!("[?-?] - [{}:{}:{}]", file!(), line!(), column!());
    };
    ($lit:literal) => {
        println!("[?-?] {}", $lit);
    };
    ($($val:expr$(,)?)*) => {
        println!("[?-?] - [{}:{}:{}]", file!(), line!(), column!());
        $({$crate::_debug_print!($val)})*;
    };
}

#[macro_export] macro_rules! info {
    () => {
        println!("[^-^] - [{}:{}:{}]", file!(), line!(), column!());
    };
    ($lit:literal) => {
        println!("[^-^] {}", $lit);
    };
    ($arg:expr) => {
        println!("[^-^] {} => {}", stringify!($arg), $arg);
    };
    ($($arg:tt)*) => {
        println!("[^-^] {}", format!($($arg)*));
    };
}

#[macro_export] macro_rules! error {
    () => {
        println!("[TwT] ! [{}:{}:{}]", file!(), line!(), column!());
    };
    ($arg:literal) => {
        println!("[TwT] {}", $arg);
    };
    ($arg:expr) => {
        println!("[TwT] [{}:{}:{}] \n\t => {} => {}", file!(), line!(), column!(), stringify!($arg), $arg);
    };
    ($($arg:tt)*) => {
        eprintln!("[TwT] [{}:{}:{}] \n\t => {}", file!(), line!(), column!(), format!($($arg)*));
    };
}
