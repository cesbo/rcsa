use {
    std::mem::MaybeUninit,
    crate::{
        key::expand_key,
        Bit,
        Nibble,
    },
};


// Block cypher

const BLOCK_SBOX: [u8; 0x100] = [
    0x3A, 0xEA, 0x68, 0xFE, 0x33, 0xE9, 0x88, 0x1A, 0x83, 0xCF, 0xE1, 0x7F, 0xBA, 0xE2, 0x38, 0x12,
    0xE8, 0x27, 0x61, 0x95, 0x0C, 0x36, 0xE5, 0x70, 0xA2, 0x06, 0x82, 0x7C, 0x17, 0xA3, 0x26, 0x49,
    0xBE, 0x7A, 0x6D, 0x47, 0xC1, 0x51, 0x8F, 0xF3, 0xCC, 0x5B, 0x67, 0xBD, 0xCD, 0x18, 0x08, 0xC9,
    0xFF, 0x69, 0xEF, 0x03, 0x4E, 0x48, 0x4A, 0x84, 0x3F, 0xB4, 0x10, 0x04, 0xDC, 0xF5, 0x5C, 0xC6,
    0x16, 0xAB, 0xAC, 0x4C, 0xF1, 0x6A, 0x2F, 0x3C, 0x3B, 0xD4, 0xD5, 0x94, 0xD0, 0xC4, 0x63, 0x62,
    0x71, 0xA1, 0xF9, 0x4F, 0x2E, 0xAA, 0xC5, 0x56, 0xE3, 0x39, 0x93, 0xCE, 0x65, 0x64, 0xE4, 0x58,
    0x6C, 0x19, 0x42, 0x79, 0xDD, 0xEE, 0x96, 0xF6, 0x8A, 0xEC, 0x1E, 0x85, 0x53, 0x45, 0xDE, 0xBB,
    0x7E, 0x0A, 0x9A, 0x13, 0x2A, 0x9D, 0xC2, 0x5E, 0x5A, 0x1F, 0x32, 0x35, 0x9C, 0xA8, 0x73, 0x30,
    0x29, 0x3D, 0xE7, 0x92, 0x87, 0x1B, 0x2B, 0x4B, 0xA5, 0x57, 0x97, 0x40, 0x15, 0xE6, 0xBC, 0x0E,
    0xEB, 0xC3, 0x34, 0x2D, 0xB8, 0x44, 0x25, 0xA4, 0x1C, 0xC7, 0x23, 0xED, 0x90, 0x6E, 0x50, 0x00,
    0x99, 0x9E, 0x4D, 0xD9, 0xDA, 0x8D, 0x6F, 0x5F, 0x3E, 0xD7, 0x21, 0x74, 0x86, 0xDF, 0x6B, 0x05,
    0x8E, 0x5D, 0x37, 0x11, 0xD2, 0x28, 0x75, 0xD6, 0xA7, 0x77, 0x24, 0xBF, 0xF0, 0xB0, 0x02, 0xB7,
    0xF8, 0xFC, 0x81, 0x09, 0xB1, 0x01, 0x76, 0x91, 0x7D, 0x0F, 0xC8, 0xA0, 0xF2, 0xCB, 0x78, 0x60,
    0xD1, 0xF7, 0xE0, 0xB5, 0x98, 0x22, 0xB3, 0x20, 0x1D, 0xA6, 0xDB, 0x7B, 0x59, 0x9F, 0xAE, 0x31,
    0xFB, 0xD3, 0xB6, 0xCA, 0x43, 0x72, 0x07, 0xF4, 0xD8, 0x41, 0x14, 0x55, 0x0D, 0x54, 0x8B, 0xB9,
    0xAD, 0x46, 0x0B, 0xAF, 0x80, 0x52, 0x2C, 0xFA, 0x8C, 0x89, 0x66, 0xFD, 0xB2, 0xA9, 0x9B, 0xC0,
];


// bit_permutation!(sbox_out, [1, 7, 5, 4, 2, 6, 0, 3])
const BLOCK_PERM: [u8; 0x100] = [
    0x00, 0x02, 0x80, 0x82, 0x20, 0x22, 0xA0, 0xA2, 0x10, 0x12, 0x90, 0x92, 0x30, 0x32, 0xB0, 0xB2,
    0x04, 0x06, 0x84, 0x86, 0x24, 0x26, 0xA4, 0xA6, 0x14, 0x16, 0x94, 0x96, 0x34, 0x36, 0xB4, 0xB6,
    0x40, 0x42, 0xC0, 0xC2, 0x60, 0x62, 0xE0, 0xE2, 0x50, 0x52, 0xD0, 0xD2, 0x70, 0x72, 0xF0, 0xF2,
    0x44, 0x46, 0xC4, 0xC6, 0x64, 0x66, 0xE4, 0xE6, 0x54, 0x56, 0xD4, 0xD6, 0x74, 0x76, 0xF4, 0xF6,
    0x01, 0x03, 0x81, 0x83, 0x21, 0x23, 0xA1, 0xA3, 0x11, 0x13, 0x91, 0x93, 0x31, 0x33, 0xB1, 0xB3,
    0x05, 0x07, 0x85, 0x87, 0x25, 0x27, 0xA5, 0xA7, 0x15, 0x17, 0x95, 0x97, 0x35, 0x37, 0xB5, 0xB7,
    0x41, 0x43, 0xC1, 0xC3, 0x61, 0x63, 0xE1, 0xE3, 0x51, 0x53, 0xD1, 0xD3, 0x71, 0x73, 0xF1, 0xF3,
    0x45, 0x47, 0xC5, 0xC7, 0x65, 0x67, 0xE5, 0xE7, 0x55, 0x57, 0xD5, 0xD7, 0x75, 0x77, 0xF5, 0xF7,
    0x08, 0x0A, 0x88, 0x8A, 0x28, 0x2A, 0xA8, 0xAA, 0x18, 0x1A, 0x98, 0x9A, 0x38, 0x3A, 0xB8, 0xBA,
    0x0C, 0x0E, 0x8C, 0x8E, 0x2C, 0x2E, 0xAC, 0xAE, 0x1C, 0x1E, 0x9C, 0x9E, 0x3C, 0x3E, 0xBC, 0xBE,
    0x48, 0x4A, 0xC8, 0xCA, 0x68, 0x6A, 0xE8, 0xEA, 0x58, 0x5A, 0xD8, 0xDA, 0x78, 0x7A, 0xF8, 0xFA,
    0x4C, 0x4E, 0xCC, 0xCE, 0x6C, 0x6E, 0xEC, 0xEE, 0x5C, 0x5E, 0xDC, 0xDE, 0x7C, 0x7E, 0xFC, 0xFE,
    0x09, 0x0B, 0x89, 0x8B, 0x29, 0x2B, 0xA9, 0xAB, 0x19, 0x1B, 0x99, 0x9B, 0x39, 0x3B, 0xB9, 0xBB,
    0x0D, 0x0F, 0x8D, 0x8F, 0x2D, 0x2F, 0xAD, 0xAF, 0x1D, 0x1F, 0x9D, 0x9F, 0x3D, 0x3F, 0xBD, 0xBF,
    0x49, 0x4B, 0xC9, 0xCB, 0x69, 0x6B, 0xE9, 0xEB, 0x59, 0x5B, 0xD9, 0xDB, 0x79, 0x7B, 0xF9, 0xFB,
    0x4D, 0x4F, 0xCD, 0xCF, 0x6D, 0x6F, 0xED, 0xEF, 0x5D, 0x5F, 0xDD, 0xDF, 0x7D, 0x7F, 0xFD, 0xFF,
];


const SBOX1: [u8; 0x20] = [
    2,0,1,1,2,3,3,0,
    3,2,2,0,1,1,0,3,
    0,3,3,0,2,2,1,1,
    2,2,0,3,1,1,3,0
];


const SBOX2: [u8; 0x20] = [
    3,1,0,2,2,3,3,0,
    1,3,2,1,0,0,1,2,
    3,1,0,3,3,2,0,2,
    0,0,1,2,2,1,3,1
];


const SBOX3: [u8; 0x20] = [
    2,0,1,2,2,3,3,1,
    1,1,0,3,3,0,2,0,
    1,3,0,1,3,0,2,2,
    2,0,1,2,0,3,3,1
];


const SBOX4: [u8; 0x20] = [
    3,1,2,3,0,2,1,2,
    1,2,0,1,3,0,0,3,
    1,0,3,1,2,3,0,3,
    0,3,2,0,1,2,2,1
];


const SBOX5: [u8; 0x20] = [
    2,0,0,1,3,2,3,2,
    0,1,3,3,1,0,2,1,
    2,3,2,0,0,3,1,1,
    1,0,3,2,3,1,0,2
];


const SBOX6: [u8; 0x20] = [
    0,1,2,3,1,2,2,0,
    0,1,3,0,2,3,1,3,
    2,3,0,2,3,0,1,1,
    2,1,1,2,0,3,3,0
];


const SBOX7P: [u8; 0x20] = [
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
    0xFF, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF,
    0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF,
];


const SBOX7Q: [u8; 0x20] = [
    0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF,
    0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF,
    0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00,
    0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00,
];


macro_rules! bb_or {
    ($v1: expr, $v2: expr) => {
        $v1 | $v2
    };

    ($v1: expr, $v2: expr, $v3: expr) => {
        $v1 | $v2 | $v3
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr) => {
        $v1 | $v2 | $v3 | $v4
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr, $v5: expr) => {
        $v1 | $v2 | $v3 | $v4 | $v5
    };
}


macro_rules! bb_xor {
    ($v1: expr, $v2: expr) => {
        $v1 ^ $v2
    };

    ($v1: expr, $v2: expr, $v3: expr) => {
        $v1 ^ $v2 ^ $v3
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr) => {
        $v1 ^ $v2 ^ $v3 ^ $v4
    };
}


#[derive(Debug)]
pub struct Csa {
    ccw: [Nibble; 16],

    // block cypher
    kk: [u8; 56],
    t: [u8; 64],

    // stream cypher
    a: [Nibble; 42],
    b: [Nibble; 42],
    x: Nibble,
    y: Nibble,
    z: Nibble,
    d: Nibble,
    e: Nibble,
    f: Nibble,

    r: u8,
    p: u8,
    q: u8,
}


impl Default for Csa {
    fn default() -> Csa {
        Csa {
            ccw: unsafe { MaybeUninit::uninit().assume_init() },

            kk: unsafe { MaybeUninit::uninit().assume_init() },
            t: unsafe { MaybeUninit::uninit().assume_init() },

            a: unsafe { MaybeUninit::uninit().assume_init() },
            b: unsafe { MaybeUninit::uninit().assume_init() },

            x: Nibble::N0,
            y: Nibble::N0,
            z: Nibble::N0,
            d: Nibble::N0,
            e: Nibble::N0,
            f: Nibble::N0,
            r: 0,
            p: 0,
            q: 0,
        }
    }
}


impl Csa {
    pub fn set_cw(&mut self, cw: &[u8; 8]) {
        for i in 0 .. 8 {
            let tmp = cw[i] >> 4;
            self.ccw[i * 2    ] = Nibble::new(
                Bit::new(tmp),
                Bit::new(tmp >> 1),
                Bit::new(tmp >> 2),
                Bit::new(tmp >> 3),
            );

            let tmp = cw[i];
            self.ccw[i * 2 + 1] = Nibble::new(
                Bit::new(tmp),
                Bit::new(tmp >> 1),
                Bit::new(tmp >> 2),
                Bit::new(tmp >> 3),
            );
        }

        expand_key(&mut self.kk, cw);
    }

    fn block_decypher(&mut self, ib: &[u8]) {
        let mut t6: u8 = ib[6];
        let mut sbox_out: u8;

        for i in 0 .. 8 {
            self.t[56 + i] = ib[i];
        }

        for i in (0 ..= 55).rev() {
            t6 = t6 ^ self.kk[i];
            sbox_out = BLOCK_SBOX[t6 as usize];
            t6 = self.t[i + 6] ^ BLOCK_PERM[sbox_out as usize];
            self.t[i + 6] = t6;

            sbox_out = sbox_out ^ self.t[i + 8];

            self.t[i + 4] = self.t[i + 4] ^ sbox_out;
            self.t[i + 3] = self.t[i + 3] ^ sbox_out;
            self.t[i + 2] = self.t[i + 2] ^ sbox_out;
            self.t[i + 0] = sbox_out;
        }
    }

    fn stream_init(&mut self) {
        self.a[32 .. 40].copy_from_slice(&self.ccw[.. 8]);
        self.b[32 .. 40].copy_from_slice(&self.ccw[8 ..]);

        self.a[40] = Nibble::N0;
        self.a[41] = Nibble::N0;

        self.b[40] = Nibble::N0;
        self.b[41] = Nibble::N0;

        self.x = Nibble::N0;
        self.y = Nibble::N0;
        self.z = Nibble::N0;
        self.d = Nibble::N0;
        self.e = Nibble::N0;
        self.f = Nibble::N0;
        self.r = 0;
        self.p = 0;
        self.q = 0;
    }

    fn b_group_xor(&mut self, skip: usize) {
        let tmp = Nibble::new(
            bb_xor!(
                self.b[skip + 9].2,
                self.b[skip + 6].3,
                self.b[skip + 3].1,
                self.b[skip + 8].0
            ),
            bb_xor!(
                self.b[skip + 5].3,
                self.b[skip + 8].2,
                self.b[skip + 4].0,
                self.b[skip + 5].1
            ),
            bb_xor!(
                self.b[skip + 6].0,
                self.b[skip + 8].1,
                self.b[skip + 3].3,
                self.b[skip + 4].2
            ),
            bb_xor!(
                self.b[skip + 3].0,
                self.b[skip + 6].1,
                self.b[skip + 7].2,
                self.b[skip + 9].3
            ),
        );

        self.d = self.e ^ self.z ^ tmp;

        let tmp = self.f;
        if self.q != 0 {
            // TODO: replace
            let z = (self.z.3 << 3) | (self.z.2 << 2) | (self.z.1 << 1) | self.z.0;
            let e = (self.e.3 << 3) | (self.e.2 << 2) | (self.e.1 << 1) | self.e.0;
            let f = z.unwrap() + e.unwrap() + self.r;
            self.r = f >> 4;
            self.f = Nibble::new(
                Bit::new(f),
                Bit::new(f >> 1),
                Bit::new(f >> 2),
                Bit::new(f >> 3),
            );
        } else {
            self.f = self.e;
        }
        self.e = tmp;
    }

    fn a_group_xor(&mut self, skip: usize) {
        // TODO: bit-ops instead of s-boxes
        let s1 = bb_or!(
            self.a[skip + 4].0 << 4,
            self.a[skip + 1].2 << 3,
            self.a[skip + 6].1 << 2,
            self.a[skip + 7].3 << 1,
            self.a[skip + 9].0
        );
        let s1 = SBOX1[s1 as usize];

        let s2 = bb_or!(
            self.a[skip + 2].1 << 4,
            self.a[skip + 3].2 << 3,
            self.a[skip + 6].3 << 2,
            self.a[skip + 7].0 << 1,
            self.a[skip + 9].1
        );
        let s2 = SBOX2[s2 as usize];

        let s3 = bb_or!(
            self.a[skip + 1].3 << 4,
            self.a[skip + 2].0 << 3,
            self.a[skip + 5].1 << 2,
            self.a[skip + 5].3 << 1,
            self.a[skip + 6].2
        );
        let s3 = SBOX3[s3 as usize];

        let s4 = bb_or!(
            self.a[skip + 3].3 << 4,
            self.a[skip + 1].1 << 3,
            self.a[skip + 2].3 << 2,
            self.a[skip + 4].2 << 1,
            self.a[skip + 8].0
        );
        let s4 = SBOX4[s4 as usize];

        let s5 = bb_or!(
            self.a[skip + 5].2 << 4,
            self.a[skip + 4].3 << 3,
            self.a[skip + 6].0 << 2,
            self.a[skip + 8].1 << 1,
            self.a[skip + 9].2
        );
        let s5 = SBOX5[s5 as usize];

        let s6 = bb_or!(
            self.a[skip + 3].1 << 4,
            self.a[skip + 4].1 << 3,
            self.a[skip + 5].0 << 2,
            self.a[skip + 7].2 << 1,
            self.a[skip + 9].3
        );
        let s6 = SBOX6[s6 as usize];

        let s7 = bb_or!(
            self.a[skip + 2].2 << 4,
            self.a[skip + 3].0 << 3,
            self.a[skip + 7].1 << 2,
            self.a[skip + 8].2 << 1,
            self.a[skip + 8].3
        );

        self.x = Nibble::new(
            (s1 >> 1) & 0x01,
            (s2 >> 1) & 0x01,
            s3 & 0x01,
            s4 & 0x01,
        );

        self.y = Nibble::new(
            (s3 >> 1) & 0x01,
            (s4 >> 1) & 0x01,
            s5 & 0x01,
            s6 & 0x01,
        );

        self.z = Nibble::new(
            (s5 >> 1) & 0x01,
            (s6 >> 1) & 0x01,
            s1 & 0x01,
            s2 & 0x01,
        );

        self.p = SBOX7P[s7 as usize];
        self.q = SBOX7Q[s7 as usize];
    }

    fn stream_cypher_init(&mut self, sb: &[u8]) {
        for i in 0 .. 8 {
            for j in 0 .. 4 {
                let skip = 31 - i * 4 - j;

                // TODO: wrap many packets
                let tmp = (sb[i] >> ((1 - (j & 1)) << 2)) & 0x0F;
                let tmp = Nibble::new(
                    Bit::new(tmp >> 0),
                    Bit::new(tmp >> 1),
                    Bit::new(tmp >> 2),
                    Bit::new(tmp >> 3),
                );
                self.a[skip] = self.a[skip + 10] ^ self.x ^ self.d ^ tmp;

                // TODO: wrap many packets
                let tmp = (sb[i] >> ((j & 1) << 2)) & 0x0F;
                let tmp = Nibble::new(
                    Bit::new(tmp >> 0),
                    Bit::new(tmp >> 1),
                    Bit::new(tmp >> 2),
                    Bit::new(tmp >> 3),
                );
                self.b[skip] = self.b[skip + 10] ^ self.y ^ self.b[skip + 7] ^ tmp;

                if self.p != 0 {
                    self.b[skip] = self.b[skip].rotate_left();
                }

                self.b_group_xor(skip);
                self.a_group_xor(skip);
            }
        }

        self.a.copy_within(0 .. 10, 32);
        self.b.copy_within(0 .. 10, 32);
    }

    fn stream_cypher(&mut self, cb: &mut [u8]) {
        for i in 0 .. 8 {
            for j in 0 .. 4 {
                let skip = 31 - i * 4 - j;

                self.a[skip] = self.a[skip + 10] ^ self.x;
                self.b[skip] = self.b[skip + 10] ^ self.y ^ self.b[skip + 7];

                if self.p != 0 {
                    self.b[skip] = self.b[skip].rotate_left();
                }

                self.b_group_xor(skip);
                self.a_group_xor(skip);

                let tmp = ((self.d.2 ^ self.d.3) << 1) | (self.d.0 ^ self.d.1);

                // TODO: unwrap many packets
                cb[i] = cb[i] << 2 | tmp.unwrap();
            }
        }

        self.a.copy_within(0 .. 10, 32);
        self.b.copy_within(0 .. 10, 32);
    }

    // Bit - структура содержи 1 бит пакета, bi_u8 при параллельной обработке
    // может содержать по одному биту из 8 пакетов
    // Nibble - полубайт. Содержит 4 бита

    pub fn decrypt(&mut self, src: &[u8], dest: &mut [u8]) {
        let mut block: [u8; 8] = unsafe { MaybeUninit::uninit().assume_init() };

        for i in 0 .. 4 {
            dest[i] = src[i];
        }

        for i in 0 .. 8 {
            block[i] = src[4 + i];
        }

        self.stream_init();
        self.stream_cypher_init(&block);

        for i in 0 .. 22 {
            self.block_decypher(&block);
            self.stream_cypher(&mut block);

            for j in 0 .. 8 {
                block[j] = block[j] ^ src[4 + i * 8 + 8 + j];
                dest[4 + i * 8 + j] = block[j] ^ self.t[j]
            }
        }

        self.block_decypher(&block);

        for i in 0 .. 8 {
            dest[180 + i] = self.t[i];
        }
    }
}
