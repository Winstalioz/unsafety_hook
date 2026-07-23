use windows_sys::{Win32::Foundation::HANDLE, core::BOOL};

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct FLOATING_SAVE_AREA {
    pub ControlWord: u32,
    pub StatusWord: u32,
    pub TagWord: u32,
    pub ErrorOffset: u32,
    pub ErrorSelector: u32,
    pub DataOffset: u32,
    pub DataSelector: u32,
    pub RegisterArea: [u8; 80],
    pub Cr0NpxState: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct CONTEXT_X86 {
    pub ContextFlags: u32,
    pub Dr0: u32,
    pub Dr1: u32,
    pub Dr2: u32,
    pub Dr3: u32,
    pub Dr6: u32,
    pub Dr7: u32,
    pub FloatSave: FLOATING_SAVE_AREA,
    pub SegGs: u32,
    pub SegFs: u32,
    pub SegEs: u32,
    pub SegDs: u32,
    pub Edi: u32,
    pub Esi: u32,
    pub Ebx: u32,
    pub Edx: u32,
    pub Ecx: u32,
    pub Eax: u32,
    pub Ebp: u32,
    pub Eip: u32,
    pub SegCs: u32,
    pub EFlags: u32,
    pub Esp: u32,
    pub SegSs: u32,
    pub ExtendedRegisters: [u8; 512], // MAXIMUM_SUPPORTED_EXTENSION
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub(crate) fn GetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT_X86) -> BOOL;
}
