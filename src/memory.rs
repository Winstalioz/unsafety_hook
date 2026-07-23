use windows_sys::Win32::{
    Foundation::{FALSE, HMODULE},
    System::{
        LibraryLoader::GetModuleHandleA,
        Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect},
        ProcessStatus::{GetModuleInformation, MODULEINFO},
        Threading::GetCurrentProcess,
    },
};

/// Writes a value of type `T` to the given address without modifying memory protection.
///
/// # Safety
///
/// - `address` must be a valid, writable pointer to a location that can hold `T`.
/// - The memory at `address` must not be protected (e.g. must already be writable).
///   For protected memory such as code sections, use [`write_safe`] instead.
/// - No other thread must be reading or writing the same memory concurrently.
pub unsafe fn write<T: Copy>(address: usize, value: T) {
    unsafe { std::ptr::write(address as *mut T, value) }
}

/// Writes a value of type `T` to the given address, temporarily lifting memory protection.
///
/// Temporarily changes the page protection to `PAGE_EXECUTE_READWRITE`, writes the value,
/// then restores the original protection. Suitable for patching code sections.
///
/// Returns `true` on success, `false` if either `VirtualProtect` call fails.
///
/// # Safety
///
/// - `address` must be a valid pointer to a memory region of at least `size_of::<T>()` bytes.
/// - No other thread must be reading or writing the same memory concurrently.
pub unsafe fn write_safe<T: Copy>(address: usize, value: T) -> bool {
    let size = std::mem::size_of::<T>();
    let mut old_prot = 0;
    let addr_ptr = address as *const std::ffi::c_void;
    unsafe {
        if VirtualProtect(addr_ptr, size, PAGE_EXECUTE_READWRITE, &mut old_prot) == FALSE {
            return false;
        }
        self::write::<T>(address, value);
        VirtualProtect(addr_ptr, size, old_prot, &mut old_prot);
    }
    true
}

/// Reads a value of type `T` from the given address.
///
/// # Safety
///
/// - `address` must be a valid, readable pointer to a properly initialized value of type `T`.
/// - The memory must remain valid and unmodified for the duration of the read.
pub unsafe fn read<T: Copy>(address: usize) -> T {
    unsafe { std::ptr::read(address as *const T) }
}

/// Reads a value of type `T` from the given address, temporarily lifting memory protection.
///
/// Returns `Some(T)` on success, `None` if either `VirtualProtect` call fails.
///
/// # Safety
///
/// - `address` must be a valid pointer to a properly initialized value of type `T`.
/// - The memory must remain valid for the duration of the read.
pub unsafe fn read_safe<T: Copy>(address: usize) -> Option<T> {
    let size = std::mem::size_of::<T>();
    let mut old_prot = 0;
    let addr_ptr = address as *const std::ffi::c_void;
    unsafe {
        if VirtualProtect(addr_ptr, size, PAGE_EXECUTE_READWRITE, &mut old_prot) == FALSE {
            return None;
        }
        let result = self::read::<T>(address);
        if VirtualProtect(addr_ptr, size, old_prot, &mut old_prot) == FALSE {
            return None;
        }
        Some(result)
    }
}

/// Returns the base address and size (in bytes) of a loaded module.
///
/// Passes `None` to get information about the current process executable.
/// Passes `Some("samp.dll")` (or any other module name) to query a specific DLL.
///
/// Returns `None` if the module is not loaded or information cannot be retrieved.
fn get_module_info(name: Option<&str>) -> Option<(usize, usize)> {
    unsafe {
        let handle: HMODULE = match name {
            Some(n) => {
                let cstr = std::ffi::CString::new(n).ok()?;
                GetModuleHandleA(cstr.as_ptr() as *const u8)
            }
            None => GetModuleHandleA(std::ptr::null()),
        };

        if handle.is_null() {
            return None;
        }

        let mut info: MODULEINFO = std::mem::zeroed();
        if GetModuleInformation(
            GetCurrentProcess(),
            handle,
            &mut info,
            std::mem::size_of::<MODULEINFO>() as u32,
        ) == 0
        {
            return None;
        }

        Some((info.lpBaseOfDll as usize, info.SizeOfImage as usize))
    }
}

/// Scans a loaded module's memory for a byte pattern, with wildcard support.
///
/// `module_name` is the name of the module to scan (e.g. `Some("samp.dll")`),
/// or `None` to scan the current process executable.
///
/// `bytes` is the pattern to search for. `mask` is a string of the same length
/// where `'x'` means the corresponding byte must match exactly, and `'?'` is a
/// wildcard that matches any byte.
///
/// Returns the address of the first match, or `None` if no match is found or
/// the module cannot be located.
///
/// # Example
///
/// ```no_run
/// // Find a function in samp.dll across multiple SA:MP versions
/// // without hardcoding version-specific addresses.
/// let addr = unsafe {
///     pattern_scan(
///         Some("samp.dll"),
///         b"\x55\x8B\xEC\x00\x56\x57",
///         "xxx?xx",
///     )
/// };
/// ```
///
/// # Safety
///
/// - The target module must be loaded and its memory must remain valid
///   for the duration of the scan.
/// - `bytes` and `mask` must be the same length.
pub unsafe fn pattern_scan(module_name: Option<&str>, bytes: &[u8], mask: &str) -> Option<usize> {
    debug_assert_eq!(bytes.len(), mask.len());

    let (module_base, module_size) = get_module_info(module_name)?;

    let mask_b = mask.as_bytes();
    let bytes_len = bytes.len();

    'on_module: for i in 0..module_size.saturating_sub(bytes_len) {
        if unsafe { self::read::<u8>(module_base + i) } != bytes[0] {
            continue;
        }
        for j in 0..bytes_len {
            if mask_b[j] != b'?' && unsafe { self::read::<u8>(module_base + i + j) } != bytes[j] {
                continue 'on_module;
            }
        }
        return Some(module_base + i);
    }
    None
}
