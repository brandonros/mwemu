
use crate::{constants, emu, winapi::winapi64::kernel32::set_last_error};

pub fn GetComputerNameW(emu: &mut emu::Emu) {
    let buff_ptr = emu.regs().rcx;   // LPWSTR lpBuffer
    let size_ptr = emu.regs().rdx;   // LPDWORD nSize

    log::info!(
        "{}** {} kernel32!GetComputerNameW lpBuffer: 0x{:x} nSize: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        buff_ptr,
        size_ptr,
        emu.colors.nc
    );

    // Check if size pointer is valid
    if size_ptr == 0 || !emu.maps.is_mapped(size_ptr) {
        log::info!("{}** {} GetComputerNameW: Invalid nSize pointer {}", 
                  emu.colors.light_red, emu.pos, emu.colors.nc);
        set_last_error(constants::ERROR_INVALID_PARAMETER);
        emu.regs_mut().rax = constants::FALSE;
        return;
    }

    // Read current buffer size (in characters)
    let buffer_size = emu.maps.read_dword(size_ptr).expect("Cannot read buffer size") as usize;
    
    // Calculate required size in characters
    let computer_name_chars = constants::HOST_NAME.chars().count();
    let required_size_with_null = computer_name_chars + 1; // +1 for null terminator

    // Check if output buffer is valid (only if buffer_size > 0)
    if buffer_size > 0 && (buff_ptr == 0 || !emu.maps.is_mapped(buff_ptr)) {
        log::info!("{}** {} GetComputerNameW: Invalid lpBuffer pointer {}", 
                  emu.colors.light_red, emu.pos, emu.colors.nc);
        set_last_error(constants::ERROR_INVALID_PARAMETER);
        emu.regs_mut().rax = constants::FALSE;
        return;
    }

    // Check if buffer is large enough
    if buffer_size < required_size_with_null {
        log::info!(
            "{}** {} GetComputerNameW: Buffer too small. Required: {}, Provided: {} {}",
            emu.colors.light_red,
            emu.pos,
            required_size_with_null,
            buffer_size,
            emu.colors.nc
        );
        // Set size to required size (including null terminator)
        emu.maps.write_dword(size_ptr, required_size_with_null as u32);
        set_last_error(constants::ERROR_BUFFER_OVERFLOW);
        emu.regs_mut().rax = constants::FALSE;
        return;
    }

    // Buffer is large enough, write the computer name
    emu.maps.write_wide_string(buff_ptr, constants::HOST_NAME);
    
    // On success, write the number of characters copied (NOT including null terminator)
    emu.maps.write_dword(size_ptr, computer_name_chars as u32);

    log::info!(
        "{}** {} kernel32!GetComputerNameW returning: '{}' (chars: {}) {}",
        emu.colors.light_red,
        emu.pos,
        constants::HOST_NAME,
        computer_name_chars,
        emu.colors.nc
    );

    emu.regs_mut().rax = constants::TRUE;
}
