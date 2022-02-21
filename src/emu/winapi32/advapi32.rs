use crate::emu;


pub fn gateway(addr:u32, emu:&mut emu::Emu) {
    match addr {
        0x77733553 => StartServiceCtrlDispatcherA(emu),
        0x776fa965 => StartServiceCtrlDispatcherW(emu),
        _ => panic!("calling unimplemented advapi32 API 0x{:x}", addr)
    }
}

fn StartServiceCtrlDispatcherA(emu:&mut emu::Emu) {
    let service_table_entry_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("advapi32!StartServiceCtrlDispatcherA error reading service_table_entry pointer");

    let service_name = emu.maps.read_dword(service_table_entry_ptr as u64).expect("advapi32!StartServiceCtrlDispatcherA error reading service_name");
    let service_name = emu.maps.read_dword((service_table_entry_ptr+4) as u64).expect("advapi32!StartServiceCtrlDispatcherA error reading service_name");

    emu.stack_pop32(false);
    emu.regs.set_eax(1);
}

fn StartServiceCtrlDispatcherW(emu:&mut emu::Emu) {
    let service_table_entry_ptr = emu.maps.read_dword(emu.regs.get_esp()).expect("advapi32!StartServiceCtrlDispatcherW error reading service_table_entry pointer");

    emu.stack_pop32(false);
    emu.regs.set_eax(1);
}   