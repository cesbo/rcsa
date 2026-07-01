/// Bits permutation.
///
/// ```ignore
/// (((v >> 0) & 1) << arr[0]) | (((v >> 1) & 1) << arr[1]) | ...
/// ```
macro_rules! bit_permutation {
    ($v:ident, $pos:expr, [$next:literal]) => {
        (($v >> $pos) & 1) << $next
    };

    ($v:ident, $pos:expr, [$next:literal, $($arr:literal),+ $(,)?]) => {
        bit_permutation!($v, $pos, [$next]) | bit_permutation!($v, $pos + 1, [$($arr),+])
    };

    ($v:ident, [$($arr:literal),+ $(,)?]) => {
        bit_permutation!($v, 0, [$($arr),+])
    };
}

fn key_permutation(data: u64) -> u64 {
    bit_permutation!(
        data,
        [
            19, 27, 55, 46, 1, 15, 36, 22, 56, 61, 39, 21, 54, 58, 50, 28, 7, 29, 51, 6, 33, 35,
            20, 16, 47, 30, 32, 63, 10, 11, 4, 38, 62, 26, 40, 18, 12, 52, 37, 53, 23, 59, 41, 17,
            31, 0, 25, 43, 44, 14, 2, 13, 45, 48, 3, 60, 49, 8, 34, 5, 9, 42, 57, 24
        ]
    )
}

macro_rules! expand_key {
    ($cw: ident, $kk:ident, $offset:expr, [$magic:literal]) => {
        let k = $cw ^ $magic;
        for j in 0 .. 8 {
            $kk[$offset + j] = (k >> (j * 8)) as u8;
        }
    };

    ($cw:ident, $kk:ident, $offset:expr, [$magic:literal, $($arr:literal),+ $(,)?]) => {
        expand_key!($cw, $kk, $offset, [$magic]);
        $cw = key_permutation($cw);
        expand_key!($cw, $kk, $offset - 8, [$($arr),+]);
    };
}

/// Expands key with bits permutation
/// 2.1 Breaking DVB-CSA
#[inline]
pub fn expand_key(kk: &mut [u8; 56], cw: &[u8; 8]) {
    let mut tmp = u64::from_le_bytes(*cw);
    expand_key!(
        tmp,
        kk,
        48,
        [
            0x0606060606060606,
            0x0505050505050505,
            0x0404040404040404,
            0x0303030303030303,
            0x0202020202020202,
            0x0101010101010101,
            0x0000000000000000,
        ]
    );
}
