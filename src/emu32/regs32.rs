use crate::emu32::maps::Maps;

pub struct Regs32 {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32
}

impl Regs32 {
    pub fn new() -> Regs32 {
        Regs32{
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            esp: 0,
            eip: 0
        }
    }

    pub fn clear(&mut self) {
        self.eax = 0;
        self.ebx = 0;
        self.ecx = 0;
        self.edx = 0;
        self.esi = 0;
        self.edi = 0;
        self.ebp = 0;
        self.esp = 0;
        self.eip = 0;
    }

    pub fn print(&self) {
        println!("regs:");
        println!("  eax: 0x{:x}", self.eax);
        println!("  ebx: 0x{:x}", self.ebx);
        println!("  ecx: 0x{:x}", self.ecx);
        println!("  edx: 0x{:x}", self.edx);
        println!("  esi: 0x{:x}", self.esi);
        println!("  edi: 0x{:x}", self.edi);
        println!("  ebp: 0x{:x}", self.ebp);
        println!("  esp: 0x{:x}", self.esp);
        println!("  eip: 0x{:x}", self.eip);
        println!("---");
    }

    pub fn get_ax(&self) -> u32 {
        return self.eax & 0xffff;
    }

    pub fn get_bx(&self) -> u32 {
        return self.ebx & 0xffff;
    }

    pub fn get_cx(&self) -> u32 {
        return self.ecx & 0xffff;
    }

    pub fn get_dx(&self) -> u32 {
        return self.edx & 0xffff;
    }

    pub fn get_si(&self) -> u32 {
        return self.esi & 0xffff;
    }

    pub fn get_di(&self) -> u32 {
        return self.edi & 0xffff;
    }

    pub fn get_ah(&self) -> u32 {
        return (self.eax & 0xff00) >> 8;
    }

    pub fn get_al(&self) -> u32 {
        return self.eax & 0xff;
    }

    pub fn get_bh(&self) -> u32 {
        return (self.ebx & 0xff00) >> 8;
    }

    pub fn get_bl(&self) -> u32 {
        return self.ebx & 0xff;
    }

    pub fn get_ch(&self) -> u32 {
        return (self.ecx & 0xff00) >> 8;
    }

    pub fn get_cl(&self) -> u32 {
        return self.ecx & 0xff;
    }

    pub fn get_dh(&self) -> u32 {
        return (self.edx & 0xff00) >> 8;
    }

    pub fn get_dl(&self) -> u32 {
        return self.edx & 0xff;
    }

    pub fn set_ax(&mut self, val:u32) {
        self.eax = self.eax & 0xffff0000;
        self.eax += val & 0x0000ffff;
    }

    pub fn set_bx(&mut self, val:u32) {
        self.ebx = self.ebx & 0xffff0000;
        self.ebx += val & 0x0000ffff;
    }

    pub fn set_cx(&mut self, val:u32) {
        self.ecx = self.ecx & 0xffff0000;
        self.ecx += val & 0x0000ffff;
    }

    pub fn set_dx(&mut self, val:u32) {
        self.edx = self.edx & 0xffff0000;
        self.edx += val & 0x0000ffff;
    }

    pub fn set_si(&mut self, val:u32) {
        self.esi = self.esi & 0xffff0000;
        self.esi += val & 0x0000ffff;
    }

    pub fn set_di(&mut self, val:u32) {
        self.edi = self.edi & 0xffff0000;
        self.edi += val & 0x0000ffff;
    }

    pub fn set_ah(&mut self, val:u32) {
        let low:u32 = self.eax & 0x000000ff;
        self.eax = (self.eax & 0xffff0000) + ((val & 0x000000ff) << 8) + low;
    }

    pub fn set_bh(&mut self, val:u32) {
        let low:u32 = self.ebx & 0x000000ff;
        self.ebx = (self.ebx & 0xffff0000) + ((val & 0x000000ff) << 8) + low;
    }

    pub fn set_ch(&mut self, val:u32) {
        let low:u32 = self.ecx & 0x000000ff;
        self.ecx = (self.ecx & 0xffff0000) + ((val & 0x000000ff) << 8) + low;
    }

    pub fn set_dh(&mut self, val:u32) {
        let low:u32 = self.edx & 0x000000ff;
        self.edx = (self.edx & 0xffff0000) + ((val & 0x000000ff) << 8) + low;
    }

    pub fn set_al(&mut self, val:u32) {
        self.eax = self.eax & 0xffffff00;
        self.eax += val & 0x000000ff;
    }
    
    pub fn set_bl(&mut self, val:u32) {
        self.ebx = self.ebx & 0xffffff00;
        self.ebx += val & 0x000000ff;
    }
    pub fn set_cl(&mut self, val:u32) {
        self.ecx = self.ecx & 0xffffff00;
        self.ecx += val & 0x000000ff;
    }
    pub fn set_dl(&mut self, val:u32) {
        self.edx = self.edx & 0xffffff00;
        self.edx += val & 0x000000ff;
    }


    pub fn get_by_name(&self, reg_name:&str) -> u32 {
        match reg_name {
            "eax" => return self.eax,
            "ebx" => return self.ebx,
            "ecx" => return self.ecx,
            "edx" => return self.edx,
            "esi" => return self.esi,
            "edi" => return self.edi,
            "ebp" => return self.ebp,
            "esp" => return self.esp,
            "eip" => return self.eip,
            "ax" => return self.get_ax(),
            "bx" => return self.get_bx(),
            "cx" => return self.get_cx(),
            "dx" => return self.get_dx(),
            "si" => return self.get_si(),
            "di" => return self.get_di(),
            "ah" => return self.get_ah(),
            "al" => return self.get_al(),
            "bh" => return self.get_bh(),
            "bl" => return self.get_bl(),
            "ch" => return self.get_ch(),
            "cl" => return self.get_cl(),
            "dh" => return self.get_dh(),
            "dl" => return self.get_dl(),
            &_ => panic!("weird register name parsed {}", reg_name),
        }
    }

    pub fn set_by_name(&mut self, reg_name:&str, value:u32) {
        match reg_name {
            "eax" => self.eax = value,
            "ebx" => self.ebx = value,
            "ecx" => self.ecx = value,
            "edx" => self.edx = value,
            "esi" => self.esi = value,
            "edi" => self.edi = value,
            "ebp" => self.ebp = value,
            "esp" => self.esp = value,
            "eip" => self.eip = value,
            "ax" => self.set_ax(value),
            "bx" => self.set_bx(value),
            "cx" => self.set_cx(value),
            "dx" => self.set_dx(value),
            "di" => self.set_di(value),
            "si" => self.set_si(value),
            "ah" => self.set_ah(value),
            "al" => self.set_al(value),
            "bh" => self.set_bh(value),
            "bl" => self.set_bl(value),
            "ch" => self.set_ch(value),
            "cl" => self.set_cl(value),
            "dh" => self.set_dh(value),
            "dl" => self.set_dl(value),
            &_ => panic!("weird register name parsed {}", reg_name),
        }
    }

    pub fn show_eax(&self, maps:&Maps) {
        if maps.is_mapped(self.eax) {
            let s = maps.read_string(self.eax);
            let w = maps.read_wide_string(self.eax);
            
            if s.len() > 1 {
                println!("eax: 0x{:x} '{}'", self.eax, s);
            } else if w.len() > 1 {
                println!("eax: 0x{:x} '{}'", self.eax, w);
            } else {
                println!("eax: 0x{:x}", self.eax);
            }
        } else {
            println!("eax: 0x{:x}", self.eax);
        }
    }

    pub fn show_ebx(&self, maps:&Maps) {
        if maps.is_mapped(self.ebx) {
            let s = maps.read_string(self.ebx);
            let w = maps.read_wide_string(self.ebx);
                
            if s.len() > 1 {
                println!("ebx: 0x{:x} '{}'", self.ebx, s);
            } else if w.len() > 1 {
                println!("ebx: 0x{:x} '{}'", self.ebx, w);
            } else {
                println!("ebx: 0x{:x}", self.ebx);
            }
        } else {
            println!("ebx: 0x{:x}", self.ebx);
        }
    }

    pub fn show_ecx(&self, maps:&Maps) {
        if maps.is_mapped(self.ecx) {
            let s = maps.read_string(self.ecx);
            let w = maps.read_wide_string(self.ecx);
   
            if s.len() > 1 {
                println!("ecx: 0x{:x} '{}'", self.ecx, s);
            } else if w.len() > 1 {
                println!("ecx: 0x{:x} '{}'", self.ecx, w);
            } else {
                println!("ecx: 0x{:x}", self.ecx);
            }
        } else {
            println!("ecx: 0x{:x}", self.ecx);
        }
    }

    pub fn show_edx(&self, maps:&Maps) {
        if maps.is_mapped(self.edx) {
            let s = maps.read_string(self.edx);
            let w = maps.read_wide_string(self.edx);

            if s.len() > 1 {
                println!("edx: 0x{:x} '{}'", self.edx, s);
            } else if w.len() > 1 {
                println!("edx: 0x{:x} '{}'", self.edx, w);
            } else {
                println!("edx: 0x{:x}", self.edx);
            }
        } else {
            println!("edx: 0x{:x}", self.eax);
        }
    }

    pub fn show_esi(&self, maps:&Maps) {
        if maps.is_mapped(self.esi) {
            let s = maps.read_string(self.esi);
            let w = maps.read_wide_string(self.esi);

            if s.len() > 1 {
                println!("esi: 0x{:x} '{}'", self.esi, s);
            } else if w.len() > 1 {
                println!("esi: 0x{:x} '{}'", self.esi, w);
            } else {
                println!("esi: 0x{:x}", self.esi);
            }
        } else {
            println!("esi: 0x{:x}", self.esi);
        }
    }

    pub fn show_edi(&self, maps:&Maps) {
        if maps.is_mapped(self.edi) {
            let s = maps.read_string(self.edi);
            let w = maps.read_wide_string(self.edi);
 
            if s.len() > 1 {
                println!("edi: 0x{:x} '{}'", self.edi, s);
            } else if w.len() > 1 {
                println!("edi: 0x{:x} '{}'", self.edi, w);
            } else {
                println!("edi: 0x{:x}", self.edi);
            }
        } else {
            println!("edi: 0x{:x}", self.edi);
        }
    }
}
