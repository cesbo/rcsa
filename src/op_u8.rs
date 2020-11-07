//! Single packet operations


#[macro_export]
macro_rules! bb_and {
    ($v1: expr, $v2: expr) => {
        $v1 & $v2
    };

    ($v1: expr, $v2: expr, $v3: expr) => {
        $v1 & $v2 & $v3
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr) => {
        $v1 & $v2 & $v3 & $v4
    };
}


#[macro_export]
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


#[macro_export]
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


#[macro_export]
macro_rules! bb_lsh {
    ($v: expr, $shift: expr) => {
        $v << $shift
    };
}


#[macro_export]
macro_rules! bb_rsh {
    ($v: expr, $shift: expr) => {
        $v >> $shift
    };
}


#[macro_export]
macro_rules! bb_add {
    ($v1: expr, $v2: expr) => {
        $v1 + $v2
    };

    ($v1: expr, $v2: expr, $v3: expr) => {
        $v1 + $v2 + $v3
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr) => {
        $v1 + $v2 + $v3 + $v4
    };
}


#[macro_export]
macro_rules! bb_and_01 {
    ($v: expr) => {
        bb_and!($v, 0x01)
    }
}


#[macro_export]
macro_rules! bb_and_0f {
    ($v: expr) => {
        bb_and!($v, 0x0F)
    }
}
