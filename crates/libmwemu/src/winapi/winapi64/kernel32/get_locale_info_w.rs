
use crate::{constants, emu};
use crate::winapi::winapi64::kernel32::{clear_last_error, LAST_ERROR};

pub fn GetLocaleInfoW(emu: &mut emu::Emu) {
    let locale = emu.regs().rcx as u64;
    let lctype = emu.regs().rdx as u64;
    let lp_lc_data = emu.regs().r8 as usize;
    let cch_data = emu.regs().r9 as usize;

    log_red!(emu, "** {} kernel32!GetLocaleInfoW locale: 0x{:x} lctype: 0x{:x} lp_lc_data: 0x{:x} cch_data: {}",
        emu.pos,
        locale,
        lctype,
        lp_lc_data,
        cch_data
    );

    let result = match lctype {
        constants::LOCALE_SLANGUAGE => "English",
        constants::LOCALE_SCOUNTRY => "United States",
        constants::LOCALE_SLIST => ",",
        constants::LOCALE_SDECIMAL => ".",
        constants::LOCALE_STHOUSAND => ",",
        constants::LOCALE_SCURRENCY => "$",
        constants::LOCALE_SDATE => "/",
        constants::LOCALE_STIME => ":",
        _ => {
            log::warn!("{} GetLocaleInfoW unhandled lctype: 0x{:x}", emu.pos, lctype);
            "." // Default fallback
        }
    };

    let required_size = result.len() + 1; // Include null terminator

    // Check if it wants buffer size
    if cch_data == 0 {
        emu.regs_mut().rax = required_size as u64;
        clear_last_error(emu);
        return;
    }

    // Validate buffer pointer
    if lp_lc_data == 0 {
        log::warn!("{} GetLocaleInfoW invalid parameter - null buffer", emu.pos);
        let mut err = LAST_ERROR.lock().unwrap();
        *err = constants::ERROR_INVALID_PARAMETER;
        emu.regs_mut().rax = 0;
        return;
    }

    // Check if buffer is too small
    if cch_data < required_size {
        log::warn!("{} buffer too small for result cch_data: {} required_size: {}", emu.pos, cch_data, required_size);
        let mut err = LAST_ERROR.lock().unwrap();
        *err = constants::ERROR_INSUFFICIENT_BUFFER;
        emu.regs_mut().rax = 0;
        return;
    }

    // Write the result to the buffer
    emu.maps.write_wide_string(lp_lc_data as u64, result);
    emu.regs_mut().rax = required_size as u64;
    clear_last_error(emu);
}
