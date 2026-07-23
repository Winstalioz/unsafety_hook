use lde::X86;
use std::{
    ffi::c_void,
    ptr::{self, null_mut},
    sync::{Mutex, OnceLock},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::{CONTEXT_CONTROL_X86, FlushInstructionCache},
            ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
        },
        Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
            VirtualFree, VirtualProtect,
        },
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread,
            SuspendThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
        },
    },
};

use crate::kernel;

static HOOKS: OnceLock<Mutex<Vec<HookDetails>>> = OnceLock::new();

fn get_hooks() -> &'static Mutex<Vec<HookDetails>> {
    HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct EFlags: u32 {
        const CF = 1 << 0;  // Carry Flag
        const PF = 1 << 2;  // Parity Flag
        const AF = 1 << 4;  // Auxiliary Carry Flag
        const ZF = 1 << 6;  // Zero Flag
        const SF = 1 << 7;  // Sign Flag
        const TF = 1 << 8;  // Trap Flag
        const IF = 1 << 9;  // Interrupt Enable Flag
        const DF = 1 << 10; // Direction Flag
        const OF = 1 << 11; // Overflow Flag
    }
}
#[repr(C)]
pub struct UnsafetyHookContext {
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub eflags: EFlags,
    pub eip: u32,
}

#[derive(Debug)]
pub enum UnsafetyHookError {
    InvalidInstructions,
    VirtualAllocFailed,
    VirtualProtectFailed(u32),
    EncodingFailed,
    SuspendFailed,
}

pub struct UnsafetyHook;

impl UnsafetyHook {
    /// Installs an inline hook at `target`, redirecting execution to `detour`.
    /// Returns a trampoline pointer that can be used to call the original function.
    ///
    /// # Safety
    ///
    /// - `target` must point to a valid, executable function with enough bytes
    ///   available to be safely overwritten (see hook length requirements).
    /// - `target` must remain valid for the lifetime of the hook (i.e. the module
    ///   containing it must not be unloaded while the hook is installed).
    /// - `detour` must be a valid function pointer with a signature compatible
    ///   with the original function being hooked.
    /// - The caller must ensure no other code concurrently modifies the bytes at
    ///   `target` while this function is installing the hook.
    pub unsafe fn inline(target: *mut (), detour: *mut ()) -> Result<*mut (), UnsafetyHookError> {
        let hook = unsafe { HookDetails::create_hook(target, detour) }?;
        let original_addr = hook.original_addr();
        get_hooks().lock().unwrap().push(hook);
        Ok(original_addr as *mut ())
    }

    /// Installs a mid-function hook at `target`, invoking `detour` with the
    /// captured CPU context before execution continues.
    ///
    /// # Safety
    ///
    /// - `target` must point to a valid instruction boundary within executable
    ///   code; hooking into the middle of a multi-byte instruction results in
    ///   undefined behavior.
    /// - `target` must remain valid for the lifetime of the hook.
    /// - `detour` must be a valid `extern "C"` function pointer matching the
    ///   expected signature, and must not unwind across the FFI boundary.
    pub unsafe fn mid(
        target: *mut (),
        detour: extern "C" fn(&mut UnsafetyHookContext),
    ) -> Result<(), UnsafetyHookError> {
        let hook = unsafe { HookDetails::mid(target, detour) }?;
        get_hooks().lock().unwrap().push(hook);
        Ok(())
    }

    /// Installs a vtable hook, replacing the function pointer at `index` in the
    /// vtable of `object` with `detour`.
    ///
    /// # Safety
    ///
    /// - `object` must be a valid pointer to an object whose first field is a
    ///   valid vtable pointer, following the standard C++ vtable layout.
    /// - `index` must be within bounds of the vtable's function pointer array.
    /// - `detour` must be a valid function pointer with a signature compatible
    ///   with the original vtable entry.
    /// - `object`'s vtable must remain valid for the lifetime of the hook.
    pub unsafe fn vtable(
        object: usize,
        index: usize,
        detour: usize,
    ) -> Result<*mut (), UnsafetyHookError> {
        let hook = unsafe { HookDetails::vtable(object, index, detour) }?;
        let original = hook.original_addr();
        get_hooks().lock().unwrap().push(hook);
        Ok(original as *mut ())
    }

    /// Removes the hook installed at `target`, restoring the original bytes
    /// at that location.
    ///
    /// Does nothing if no hook is installed at `target`.
    ///
    /// # Safety
    ///
    /// - No thread must be executing inside the hooked function, its trampoline,
    ///   or any mid-hook shellcode associated with `target` at the time of this
    ///   call, as the original bytes will be restored while the hook is removed.
    /// - Any trampoline pointer previously returned by `inline` or `vtable` for
    ///   this `target` must no longer be called after this function returns.
    pub unsafe fn remove_at(target: *mut ()) {
        get_hooks().lock().unwrap().retain_mut(|hook| {
            if hook.target_addr == target as usize {
                hook.remove();
                false
            } else {
                true
            }
        });
    }

    /// Removes all currently installed hooks, restoring original bytes at every
    /// hooked location.
    ///
    /// # Safety
    ///
    /// - All pointers previously returned by `inline`/`vtable` and any trampoline
    ///   calls derived from them must not be in use (e.g. no thread should be
    ///   executing inside a hooked function or its trampoline) when this is called,
    ///   as the original bytes will be restored while hooks are removed.
    pub unsafe fn remove_all() {
        let mut hooks = get_hooks().lock().unwrap();
        hooks.clear();
    }
}

struct HookDetails {
    target_addr: usize,
    alloc_addr: usize,
    orig_bytes: Vec<u8>,
    is_jmp: bool,
}

struct SuspendThreads {
    handles: Vec<HANDLE>,
}

impl SuspendThreads {
    fn suspend_all_threads() -> Option<Self> {
        unsafe {
            let cur_process_id = GetCurrentProcessId();
            let cur_thread_id = GetCurrentThreadId();
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut te = THREADENTRY32 {
                dwSize: size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut te) == FALSE {
                CloseHandle(snapshot);
                return None;
            }

            let mut obj: Self = Self {
                handles: Vec::new(),
            };

            loop {
                if te.th32OwnerProcessID == cur_process_id && te.th32ThreadID != cur_thread_id {
                    let thread = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        FALSE,
                        te.th32ThreadID,
                    );
                    if !thread.is_null() {
                        obj.handles.push(thread);
                        SuspendThread(thread);
                    }
                }
                if Thread32Next(snapshot, &mut te) == FALSE {
                    break;
                }
            }
            CloseHandle(snapshot);

            Some(obj)
        }
    }
    fn any_thread_in_range(&self, start: usize, end: usize) -> bool {
        for &handle in &self.handles {
            unsafe {
                let mut ctx: kernel::CONTEXT_X86 = std::mem::zeroed();
                ctx.ContextFlags = CONTEXT_CONTROL_X86;
                if kernel::GetThreadContext(handle, &mut ctx) != FALSE {
                    let eip = ctx.Eip as usize;
                    if eip >= start && eip < end {
                        return true;
                    }
                }
            }
        }
        false
    }
    fn resume_all_threads(&self) {
        for handle in &self.handles {
            unsafe {
                ResumeThread(*handle);
                CloseHandle(*handle)
            };
        }
    }
}

impl Drop for SuspendThreads {
    fn drop(&mut self) {
        self.resume_all_threads();
    }
}

impl HookDetails {
    fn get_hook_len(target: *mut ()) -> Option<(usize, Vec<Vec<u8>>)> {
        let code_slice = unsafe { std::slice::from_raw_parts(target as *const u8, 64) };
        let mut total_len = 0;
        let mut instructions = Vec::new();

        while total_len < 5 {
            let remaining = &code_slice[total_len..];
            let len = X86.ld(remaining) as usize;
            if len == 0 {
                return None;
            }
            instructions.push(remaining[..len].to_vec());
            total_len += len;
        }

        Some((total_len, instructions))
    }

    fn relocate_instruction(bytes: &[u8], old_pc: usize, new_pc: usize) -> Vec<u8> {
        let mut relocated = bytes.to_vec();
        if bytes.len() >= 5 && (bytes[0] == 0xE8 || bytes[0] == 0xE9) {
            let original_rel = i32::from_ne_bytes(bytes[1..5].try_into().unwrap());
            let absolute_target = (old_pc as isize + 5 + original_rel as isize) as usize;
            let new_rel = (absolute_target as isize - (new_pc as isize + 5)) as i32;
            relocated[1..5].copy_from_slice(&new_rel.to_ne_bytes());
        }
        relocated
    }

    unsafe fn vtable(
        object_base: usize,
        method_index: usize,
        detour: usize,
    ) -> Result<Self, UnsafetyHookError> {
        let vtable_ptr = unsafe { *(object_base as *const usize) };
        let entry_addr = vtable_ptr + (method_index * 4);
        let original_func = unsafe { *(entry_addr as *const usize) };

        let mut old_protect: u32 = 0;
        unsafe {
            if VirtualProtect(
                entry_addr as *const c_void,
                4,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ) == FALSE
            {
                return Err(UnsafetyHookError::VirtualProtectFailed(GetLastError()));
            }

            *(entry_addr as *mut usize) = detour;

            VirtualProtect(
                entry_addr as *const c_void,
                4,
                old_protect,
                &mut old_protect,
            );
        }

        Ok(Self {
            target_addr: entry_addr,
            alloc_addr: original_func,
            orig_bytes: original_func.to_ne_bytes().to_vec(),
            is_jmp: false,
        })
    }

    pub unsafe fn create_hook(target: *mut (), detour: *mut ()) -> Result<Self, UnsafetyHookError> {
        let (hook_len, instructions) =
            Self::get_hook_len(target).ok_or(UnsafetyHookError::InvalidInstructions)?;
        loop {
            let guard = match SuspendThreads::suspend_all_threads() {
                Some(g) => g,
                None => return Err(UnsafetyHookError::SuspendFailed),
            };
            if guard.any_thread_in_range(target as usize, target as usize + hook_len) {
                drop(guard);
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            if unsafe { *(target as *const u8) } == 0xE8 && hook_len == 5 {
                let res = unsafe { Self::call(target, detour) };
                return res;
            }
            if hook_len >= 5 {
                let res = unsafe { Self::jmp(target, detour, hook_len, instructions) };
                return res;
            }
            break;
        }
        Err(UnsafetyHookError::InvalidInstructions)
    }

    unsafe fn redirect_jmp(
        target: *mut (),
        to: *mut (),
        len: usize,
    ) -> Result<(), UnsafetyHookError> {
        let mut old_protect: u32 = 0;
        if unsafe {
            VirtualProtect(
                target as *const c_void,
                len,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        } == FALSE
        {
            return Err(UnsafetyHookError::VirtualProtectFailed(unsafe {
                GetLastError()
            }));
        }

        let mut patch: Vec<u8> = vec![0x90; len];
        patch[0] = 0xE9;
        let rel_addr = (to as isize - (target as isize + 5)) as i32;
        patch[1..5].copy_from_slice(&rel_addr.to_ne_bytes());

        unsafe {
            ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, len);
            FlushInstructionCache(GetCurrentProcess(), target as *const c_void, len);
            VirtualProtect(target as *const c_void, len, old_protect, &mut old_protect);
        }
        Ok(())
    }

    pub unsafe fn mid(
        target: *mut (),
        detour: extern "C" fn(&mut UnsafetyHookContext),
    ) -> Result<Self, UnsafetyHookError> {
        let (len, instructions) =
            Self::get_hook_len(target).ok_or(UnsafetyHookError::InvalidInstructions)?;
        let mut original_bytes = vec![0u8; len];
        unsafe { ptr::copy_nonoverlapping(target as *const u8, original_bytes.as_mut_ptr(), len) };

        let shellcode_mem = unsafe {
            VirtualAlloc(
                null_mut(),
                1024,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if shellcode_mem.is_null() {
            return Err(UnsafetyHookError::VirtualAllocFailed);
        }

        let shellcode_addr = shellcode_mem as usize;
        let mut sc = Vec::new();

        let default_return_addr = (target as usize + len) as u32;
        sc.push(0x68);
        sc.extend_from_slice(&default_return_addr.to_ne_bytes()); // push default_eip
        sc.push(0x9C); // pushfd
        sc.push(0x60); // pushad
        sc.extend_from_slice(&[0x89, 0xE0, 0x50]); // mov eax, esp; push eax
        sc.push(0xB8);
        sc.extend_from_slice(&(detour as usize as u32).to_ne_bytes()); // mov eax, detour
        sc.extend_from_slice(&[0xFF, 0xD0]); // call eax
        sc.extend_from_slice(&[0x83, 0xC4, 0x04]); // add esp, 4 (cdecl cleanup)
        sc.push(0x61); // popad
        sc.push(0x9D); // popfd

        let mut current_instr_pc = target as usize;
        let mut current_sc_pc = shellcode_addr + sc.len();
        for bytes in &instructions {
            let relocated = Self::relocate_instruction(bytes, current_instr_pc, current_sc_pc);
            sc.extend_from_slice(&relocated);
            current_instr_pc += bytes.len();
            current_sc_pc += bytes.len();
        }
        sc.push(0x58); // pop eax
        sc.extend_from_slice(&[0xFF, 0xE0]); // jmp eax

        unsafe { ptr::copy_nonoverlapping(sc.as_ptr(), shellcode_mem as *mut u8, sc.len()) };
        (unsafe { Self::redirect_jmp(target, shellcode_addr as *mut (), len) })?;

        Ok(Self {
            target_addr: target as usize,
            alloc_addr: shellcode_addr,
            orig_bytes: original_bytes,
            is_jmp: true,
        })
    }

    unsafe fn jmp(
        target: *mut (),
        detour: *mut (),
        len: usize,
        instructions: Vec<Vec<u8>>,
    ) -> Result<Self, UnsafetyHookError> {
        let mut original_bytes = vec![0u8; len];
        unsafe { ptr::copy_nonoverlapping(target as *const u8, original_bytes.as_mut_ptr(), len) };

        let gateway_mem = unsafe {
            VirtualAlloc(
                null_mut(),
                1024,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if gateway_mem.is_null() {
            return Err(UnsafetyHookError::VirtualAllocFailed);
        }

        let gateway_addr = gateway_mem as usize;
        let mut current_gateway_ptr = gateway_addr;
        let mut current_instr_pc = target as usize;

        for bytes in instructions {
            let relocated =
                Self::relocate_instruction(&bytes, current_instr_pc, current_gateway_ptr);
            unsafe {
                ptr::copy_nonoverlapping(
                    relocated.as_ptr(),
                    current_gateway_ptr as *mut u8,
                    relocated.len(),
                )
            };
            current_gateway_ptr += relocated.len();
            current_instr_pc += bytes.len();
        }

        let jmp_back_addr = target as usize + len;
        let rel_addr = (jmp_back_addr as isize - (current_gateway_ptr as isize + 5)) as i32;
        let mut jmp_bytes = [0xE9; 5];
        jmp_bytes[1..5].copy_from_slice(&rel_addr.to_ne_bytes());
        unsafe {
            ptr::copy_nonoverlapping(jmp_bytes.as_ptr(), current_gateway_ptr as *mut u8, 5);
            Self::redirect_jmp(target, detour, len)?;
        }

        Ok(Self {
            target_addr: target as usize,
            alloc_addr: gateway_addr,
            orig_bytes: original_bytes,
            is_jmp: true,
        })
    }

    unsafe fn call(target: *mut (), detour: *mut ()) -> Result<Self, UnsafetyHookError> {
        let mut old_protect: u32 = 0;
        unsafe {
            if VirtualProtect(
                target as *const c_void,
                5,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ) == FALSE
            {
                return Err(UnsafetyHookError::VirtualProtectFailed(GetLastError()));
            }
        }

        let mut original_bytes = vec![0x0; 5];
        unsafe { ptr::copy_nonoverlapping(target as *mut u8, original_bytes.as_mut_ptr(), 5) };

        let old_rel_addr = unsafe { *((target as usize + 1) as *const i32) };
        let original_func = (target as usize + 5).wrapping_add(old_rel_addr as usize);

        let new_rel_addr = (detour as isize - (target as isize + 5)) as i32;
        let mut patch = [0xE8u8; 5];
        patch[1..5].copy_from_slice(&new_rel_addr.to_ne_bytes());

        unsafe {
            ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, 5);
            if FlushInstructionCache(GetCurrentProcess(), target as *const c_void, 5) == FALSE {
                return Err(UnsafetyHookError::VirtualProtectFailed(GetLastError()));
            }
            if VirtualProtect(target as *const c_void, 5, old_protect, &mut old_protect) == FALSE {
                return Err(UnsafetyHookError::VirtualProtectFailed(GetLastError()));
            }
        }

        Ok(Self {
            target_addr: target as usize,
            alloc_addr: original_func,
            orig_bytes: original_bytes,
            is_jmp: false,
        })
    }

    pub fn remove(&mut self) -> bool {
        if self.orig_bytes.is_empty() {
            return true;
        }
        let mut old_prot: u32 = 0;
        unsafe {
            if VirtualProtect(
                self.target_addr as *const c_void,
                self.orig_bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_prot,
            ) == FALSE
            {
                return false;
            }
            ptr::copy_nonoverlapping(
                self.orig_bytes.as_ptr(),
                self.target_addr as *mut u8,
                self.orig_bytes.len(),
            );
            if VirtualProtect(
                self.target_addr as *const c_void,
                self.orig_bytes.len(),
                old_prot,
                &mut old_prot,
            ) == FALSE
            {
                return false;
            }
            if FlushInstructionCache(
                GetCurrentProcess(),
                self.target_addr as *const c_void,
                self.orig_bytes.len(),
            ) == FALSE
            {
                return false;
            }

            if self.is_jmp && self.alloc_addr != 0 {
                VirtualFree(self.alloc_addr as *mut c_void, 0, MEM_RELEASE);
            }
        }
        self.orig_bytes.clear();
        true
    }

    pub fn original_addr(&self) -> usize {
        self.alloc_addr
    }
}

impl Drop for HookDetails {
    fn drop(&mut self) {
        self.remove();
    }
}
