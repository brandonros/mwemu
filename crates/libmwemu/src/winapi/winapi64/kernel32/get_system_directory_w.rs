
use crate::emu;

pub fn GetSystemDirectoryW(emu: &mut emu::Emu) {
    let out_buff_ptr = emu.regs().rcx;
    let size = emu.regs().rdx as u32;

    log::info!(
        "{}** {} kernel32!GetSystemDirectoryW lpBuffer: 0x{:x} uSize: {} {}",
        emu.colors.light_red,
        emu.pos,
        out_buff_ptr,
        size,
        emu.colors.nc
    );

    let system_dir = "C:\\Windows\\System32";
    let required_length = system_dir.len() + 1; // +1 for null terminator

    // If buffer is NULL, return required size
    if out_buff_ptr == 0 {
        emu.regs_mut().rax = required_length as u64;
        return;
    }

    // Check if buffer is mapped
    if !emu.maps.is_mapped(out_buff_ptr) {
        log::error!("GetSystemDirectoryW: lpBuffer 0x{:x} is not mapped", out_buff_ptr);
        emu.regs_mut().rax = 0; // Failure
        return;
    }

    // If buffer is too small, return required size
    if (size as usize) < required_length {
        log::warn!(
            "GetSystemDirectoryW: Buffer too small. Need {} chars, got {}",
            required_length,
            size
        );
        emu.regs_mut().rax = required_length as u64;
        return;
    }

    // Buffer is large enough, write the directory
    emu.maps.write_wide_string(out_buff_ptr, system_dir);

    log::info!(
        "{}** {} GetSystemDirectoryW returning: '{}' (length: {}) {}",
        emu.colors.light_red,
        emu.pos,
        system_dir,
        system_dir.len(),
        emu.colors.nc
    );

    // Return number of characters written (NOT including null terminator)
    emu.regs_mut().rax = system_dir.len() as u64;
}
