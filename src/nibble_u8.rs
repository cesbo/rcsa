
pub struct Nibble (pub u8, pub u8, pub u8, pub u8);


impl Nibble {
    pub const fn new(b0: u8, b1: u8, b2: u8, b3: u8) -> Self {
        Nibble (b0, b1, b2, b3)
    }

    pub const X00: Self = Nibble::new(0, 0, 0, 0);
}
