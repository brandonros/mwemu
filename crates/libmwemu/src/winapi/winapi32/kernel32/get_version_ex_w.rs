use crate::emu;
use crate::structures;

pub fn GetVersionExW(emu: &mut emu::Emu) {
    let version_info_ptr =
        emu.maps
            .read_dword(emu.regs().get_esp())
            .expect("kernel32!GetVersionExW cannot read version_info_ptr param") as u64;

    log::info!(
        "{}** {} kernel32!GetVersionExW 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        version_info_ptr,
        emu.colors.nc
    );

    let os_version_info = structures::OsVersionInfoExW::new();
    os_version_info.save(version_info_ptr, &mut emu.maps);

    emu.stack_pop32(false);

    emu.regs_mut().rax = 1;
}