/// Bits permutataion
///
/// ```ignore
/// (((v >> 0) & 1) << arr[0]) | (((v >> 1) & 1) << arr[2]) | ...
/// ```
#[macro_export]
macro_rules! bit_permutation {
    ($v: ident, $pos:expr, [$next:literal]) => {
        (($v >> $pos) & 1) << $next
    };

    ($v: ident, $pos:expr, [$next:literal, $($arr:literal),+ $(,)?]) => {
        bit_permutation!($v, $pos, [$next]) | bit_permutation!($v, $pos + 1, [$($arr),+])
    };

    ($v: ident, [$($arr:literal),+ $(,)?]) => {
        bit_permutation!($v, 0, [$($arr),+])
    };
}


#[macro_export]
macro_rules! bb_bit {
    ($v: expr) => {
        bb_and_01!($v)
    };

    ($v: expr, $bit: expr) => {
        bb_bit!(bb_rsh!($v, $bit))
    };
}


#[macro_export]
macro_rules! bb_if {
    ($cond: expr, $a: expr, $b: expr) => {
        bb_xor!($a, bb_and!($cond, bb_xor!($a, $b)))
    };
}
