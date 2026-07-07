//! Bitslice boolean circuit for the DVB-CSA BLOCK cipher S-box.
//!
//! GENERATED FILE - do not edit by hand.
//! Generated from `BLOCK_SBOX`/`BLOCK_PERM` in `src/csa.rs` by an offline
//! Reed-Muller (ANF / Moebius transform) expansion per output bit, followed by
//! greedy pair-based common-subexpression elimination shared across all 8 outputs.
//! Verified exhaustively (256/256) against the original table; see the tests below,
//! which re-run the same check under `cargo test`.
//!
//! # Bit-ordering convention
//! The S-box maps an 8-bit input integer `x` to an 8-bit output integer `y`,
//! where `y == BLOCK_SBOX[x]`.
//! * Input:  `bits[i]` carries input bit `i`, i.e. logically `(x >> i) & 1`.
//! * Output: `out[o]` carries output bit `o`, i.e. logically `(y >> o) & 1`.
//!
//! Each `T` is a bitslice word: every lane holds the same logical bit for a
//! different packet, so a logical bit is represented as all-zeros (false) or
//! all-ones (true) within a lane, and `!` flips the bit in every lane at once.

use core::ops::{
    BitAnd,
    BitOr,
    BitXor,
    Not,
};

/// Bit permutation applied to the S-box output by `BLOCK_PERM` in `src/csa.rs`.
///
/// `BLOCK_PERM` is a pure bit reordering (verified for all 256 values): output-word
/// bit `i` of the S-box is moved to bit position `BLOCK_PERM_BITS[i]`. In bitslice
/// form this is a *free* relabelling of the 8 output words (no gates):
/// `permuted[BLOCK_PERM_BITS[i]] = sbox_out[i]`.
pub const BLOCK_PERM_BITS: [usize; 8] = [1, 7, 5, 4, 2, 6, 0, 3];

/// DVB-CSA block S-box as a bitslice boolean circuit.
///
/// Computes, for every lane in parallel, `out` such that the integer formed by
/// `out[o]` bits equals `BLOCK_SBOX[x]` where `x` is the integer formed by the
/// `bits[i]` bits. Uses only `& | ^ !` so it bitslices across all packets in a word.
// `inline(always)`: must collapse into the `#[target_feature(enable = "avx2")]`
// batch root so the SIMD word ops fuse to AVX2 in a default build.
#[inline(always)]
pub fn block_sbox<T>(bits: [T; 8]) -> [T; 8]
where
    T: Copy + BitAnd<Output = T> + BitOr<Output = T> + BitXor<Output = T> + Not<Output = T>,
{
    let t0 = bits[6] & bits[7];
    let t1 = bits[3] & bits[4];
    let t2 = bits[0] & bits[5];
    let t3 = bits[1] & bits[2];
    let t4 = bits[7] & t3;
    let t5 = bits[6] & t3;
    let t6 = bits[5] & t1;
    let t7 = bits[4] & t2;
    let t8 = bits[3] & t2;
    let t9 = bits[2] & t0;
    let t10 = bits[2] & bits[7];
    let t11 = bits[2] & bits[6];
    let t12 = bits[1] & t0;
    let t13 = bits[1] & bits[7];
    let t14 = bits[1] & bits[6];
    let t15 = bits[0] & t1;
    let t16 = bits[0] & bits[4];
    let t17 = bits[0] & bits[3];
    let t18 = t1 & t2;
    let t19 = t0 & t3;
    let t20 = bits[4] & bits[5];
    let t21 = bits[3] & bits[5];
    let t22 = bits[3] & t3;
    let t23 = bits[1] & bits[4];
    let t24 = bits[1] & t16;
    let t25 = bits[2] & bits[4];
    let t26 = bits[2] & t16;
    let t27 = bits[4] & t3;
    let t28 = bits[1] & t1;
    let t29 = bits[1] & t15;
    let t30 = bits[2] & t1;
    let t31 = bits[2] & t15;
    let t32 = t15 & t3;
    let t33 = bits[1] & bits[5];
    let t34 = bits[1] & t8;
    let t35 = t3 & t8;
    let t36 = bits[1] & t7;
    let t37 = bits[2] & t20;
    let t38 = bits[2] & t7;
    let t39 = bits[1] & t18;
    let t40 = bits[2] & t6;
    let t41 = bits[2] & t18;
    let t42 = bits[0] & bits[6];
    let t43 = bits[0] & t14;
    let t44 = bits[0] & t5;
    let t45 = t14 & t17;
    let t46 = t11 & t17;
    let t47 = bits[4] & bits[6];
    let t48 = bits[4] & t14;
    let t49 = bits[4] & t11;
    let t50 = t11 & t16;
    let t51 = bits[6] & t15;
    let t52 = t1 & t14;
    let t53 = t14 & t15;
    let t54 = t11 & t15;
    let t55 = t1 & t5;
    let t56 = bits[5] & t14;
    let t57 = t14 & t2;
    let t58 = bits[5] & t5;
    let t59 = t14 & t8;
    let t60 = t11 & t8;
    let t61 = t21 & t5;
    let t62 = bits[6] & t7;
    let t63 = t14 & t7;
    let t64 = t5 & t7;
    let t65 = bits[6] & t18;
    let t66 = t14 & t18;
    let t67 = t11 & t18;
    let t68 = t18 & t5;
    let t69 = bits[0] & t13;
    let t70 = bits[0] & t4;
    let t71 = bits[3] & bits[7];
    let t72 = t10 & t17;
    let t73 = t17 & t4;
    let t74 = bits[7] & t16;
    let t75 = t13 & t16;
    let t76 = t10 & t16;
    let t77 = bits[4] & t4;
    let t78 = t16 & t4;
    let t79 = t1 & t13;
    let t80 = t13 & t15;
    let t81 = t10 & t15;
    let t82 = t15 & t4;
    let t83 = bits[7] & t2;
    let t84 = bits[5] & t13;
    let t85 = bits[5] & t10;
    let t86 = bits[5] & t4;
    let t87 = t2 & t4;
    let t88 = bits[7] & t8;
    let t89 = t13 & t21;
    let t90 = t10 & t21;
    let t91 = t10 & t8;
    let t92 = t4 & t8;
    let t93 = bits[7] & t7;
    let t94 = t13 & t7;
    let t95 = t10 & t20;
    let t96 = t20 & t4;
    let t97 = t4 & t7;
    let t98 = bits[7] & t18;
    let t99 = t13 & t6;
    let t100 = t18 & t4;
    let t101 = bits[0] & t0;
    let t102 = bits[0] & t19;
    let t103 = bits[3] & t0;
    let t104 = t12 & t17;
    let t105 = t17 & t9;
    let t106 = t17 & t19;
    let t107 = t12 & t16;
    let t108 = t16 & t9;
    let t109 = t0 & t15;
    let t110 = t12 & t15;
    let t111 = t15 & t9;
    let t112 = t1 & t19;
    let t113 = bits[5] & t0;
    let t114 = t0 & t2;
    let t115 = bits[5] & t12;
    let t116 = t12 & t2;
    let t117 = t2 & t9;
    let t118 = bits[5] & t19;
    let t119 = t0 & t21;
    let t120 = t0 & t8;
    let t121 = t19 & t21;
    let t122 = t19 & t8;
    let t123 = t12 & t20;
    let t124 = t12 & t7;
    let t125 = t20 & t9;
    let t126 = t7 & t9;
    let t127 = t0 & t18;
    let t128 = t12 & t6;
    let t129 = t12 & t18;
    let t130 = bits[0] & bits[1];
    let t131 = bits[0] & bits[2];
    let t132 = bits[0] & t3;
    let t133 = bits[2] & t17;
    let t134 = t17 & t3;
    let t135 = t16 & t3;
    let t136 = bits[2] & bits[5];
    let t137 = bits[2] & t2;
    let t138 = bits[2] & t21;
    let t139 = t21 & t3;
    let t140 = t3 & t7;
    let t141 = bits[1] & t6;
    let t142 = t18 & t3;
    let t143 = bits[6] & t17;
    let t144 = bits[6] & t16;
    let t145 = t14 & t16;
    let t146 = bits[4] & t5;
    let t147 = t16 & t5;
    let t148 = t15 & t5;
    let t149 = bits[5] & bits[6];
    let t150 = t11 & t2;
    let t151 = bits[6] & t8;
    let t152 = t14 & t21;
    let t153 = t11 & t21;
    let t154 = bits[6] & t20;
    let t155 = t11 & t20;
    let t156 = t20 & t5;
    let t157 = t11 & t6;
    let t158 = bits[0] & t10;
    let t159 = bits[7] & t17;
    let t160 = bits[3] & t10;
    let t161 = bits[4] & t13;
    let t162 = bits[7] & t15;
    let t163 = t13 & t2;
    let t164 = t10 & t2;
    let t165 = bits[7] & t20;
    let t166 = t10 & t7;
    let t167 = t13 & t18;
    let t168 = t10 & t18;
    let t169 = bits[0] & t12;
    let t170 = t0 & t17;
    let t171 = bits[4] & t0;
    let t172 = bits[4] & t19;
    let t173 = t16 & t19;
    let t174 = t0 & t1;
    let t175 = t1 & t12;
    let t176 = t1 & t9;
    let t177 = t12 & t8;
    let t178 = t19 & t20;
    let t179 = t0 & t6;
    let t180 = t6 & t9;
    let t181 = bits[1] & t17;
    let t182 = bits[5] & t3;
    let t183 = t2 & t3;
    let t184 = bits[0] & t11;
    let t185 = bits[3] & bits[6];
    let t186 = bits[3] & t14;
    let t187 = bits[3] & t11;
    let t188 = bits[6] & t1;
    let t189 = t1 & t11;
    let t190 = bits[6] & t2;
    let t191 = t2 & t5;
    let t192 = t11 & t7;
    let t193 = bits[6] & t6;
    let t194 = t14 & t6;
    let t195 = t5 & t6;
    let t196 = bits[0] & bits[7];
    let t197 = bits[3] & t13;
    let t198 = t1 & t4;
    let t199 = bits[5] & bits[7];
    let t200 = t13 & t8;
    let t201 = t13 & t20;
    let t202 = bits[7] & t6;
    let t203 = t10 & t6;
    let t204 = bits[3] & t12;
    let t205 = bits[3] & t9;
    let t206 = t0 & t16;
    let t207 = bits[5] & t9;
    let t208 = t12 & t21;
    let t209 = t21 & t9;
    let t210 = t8 & t9;
    let t211 = t0 & t20;
    let t212 = t19 & t6;
    let t213 = t1 & t3;
    let t214 = bits[1] & t2;
    let t215 = bits[1] & t21;
    let t216 = bits[2] & t8;
    let t217 = bits[1] & t20;
    let t218 = t5 & t8;
    let t219 = bits[7] & t1;
    let t220 = t4 & t6;
    let t221 = bits[3] & t19;
    let t222 = bits[4] & t9;
    let t223 = t15 & t19;
    let t224 = t0 & t7;
    let t225 = t18 & t9;
    let t226 = bits[1] & bits[3];
    let t227 = bits[2] & bits[3];
    let t228 = t3 & t6;
    let t229 = bits[3] & t5;
    let t230 = t13 & t17;
    let t231 = bits[3] & t4;
    let t232 = bits[4] & bits[7];
    let t233 = bits[4] & t10;
    let t234 = t21 & t4;
    let t235 = bits[0] & t9;
    let t236 = bits[4] & t12;
    let t237 = t19 & t7;
    let t238 = bits[5] & t11;
    let t239 = t14 & t20;
    let t240 = t1 & t10;
    let t241 = bits[7] & t21;
    let t242 = t19 & t2;
    let t243 = t17 & t5;
    let t244 = t129 ^ t26;
    let t245 = t41 ^ t94;
    let t246 = t244 ^ t89;
    let t247 = t149 ^ t168;
    let t248 = t59 ^ t86;
    let t249 = t57 ^ t61;
    let t250 = t31 ^ t44;
    let t251 = t29 ^ t35;
    let t252 = t249 ^ t32;
    let t253 = t246 ^ t96;
    let t254 = t245 ^ t8;
    let t255 = t23 ^ t250;
    let t256 = t176 ^ t247;
    let t257 = t155 ^ t174;
    let t258 = t15 ^ t53;
    let t259 = t142 ^ t257;
    let t260 = t128 ^ t253;
    let t261 = t12 ^ t260;
    let t262 = t111 ^ t254;
    let t263 = t101 ^ t24;
    let t264 = t0 ^ t263;
    let t265 = t84 ^ t85;
    let t266 = t51 ^ t90;
    let t267 = t47 ^ t82;
    let t268 = t36 ^ t48;
    let t269 = t268 ^ t3;
    let t270 = t264 ^ t58;
    let t271 = t262 ^ t88;
    let t272 = t261 ^ t73;
    let t273 = t258 ^ t60;
    let t274 = t256 ^ t259;
    let t275 = t255 ^ t55;
    let t276 = t252 ^ t39;
    let t277 = t251 ^ t270;
    let t278 = t25 ^ t66;
    let t279 = t248 ^ t92;
    let t280 = t190 ^ t208;
    let t281 = t170 ^ t171;
    let t282 = t169 ^ t212;
    let t283 = t156 ^ t173;
    let t284 = t154 ^ t180;
    let t285 = t150 ^ t274;
    let t286 = t147 ^ t285;
    let t287 = t141 ^ t281;
    let t288 = t139 ^ t159;
    let t289 = t137 ^ t287;
    let t290 = t124 ^ t276;
    let t291 = t123 ^ t38;
    let t292 = t115 ^ t291;
    let t293 = t114 ^ t273;
    let t294 = t11 ^ t284;
    let t295 = t108 ^ t269;
    let t296 = t107 ^ t295;
    let t297 = t105 ^ t267;
    let t298 = t104 ^ t297;
    let t299 = t102 ^ t103;
    let t300 = t1 ^ t293;
    let t301 = bits[3] ^ t18;
    let t302 = t76 ^ t97;
    let t303 = t72 ^ t80;
    let t304 = t54 ^ t77;
    let t305 = t52 ^ t71;
    let t306 = t5 ^ t50;
    let t307 = t46 ^ t65;
    let t308 = t45 ^ t87;
    let t309 = t42 ^ t75;
    let t310 = t40 ^ t7;
    let t311 = t34 ^ t99;
    let t312 = t301 ^ t304;
    let t313 = t300 ^ t307;
    let t314 = t299 ^ t306;
    let t315 = t298 ^ t93;
    let t316 = t296 ^ t312;
    let t317 = t292 ^ t68;
    let t318 = t290 ^ t70;
    let t319 = t288 ^ t289;
    let t320 = t283 ^ t294;
    let t321 = t280 ^ t282;
    let t322 = t279 ^ t311;
    let t323 = t278 ^ t316;
    let t324 = t277 ^ t49;
    let t325 = t275 ^ t318;
    let t326 = t272 ^ t324;
    let t327 = t271 ^ t313;
    let t328 = t266 ^ t4;
    let t329 = t265 ^ t43;
    let t330 = t21 ^ t78;
    let t331 = t207 ^ t286;
    let t332 = t203 ^ t331;
    let t333 = t20 ^ t325;
    let t334 = t198 ^ t332;
    let t335 = t195 ^ t206;
    let t336 = t193 ^ t334;
    let t337 = t192 ^ t197;
    let t338 = t189 ^ t202;
    let t339 = t187 ^ t336;
    let t340 = t163 ^ t319;
    let t341 = t16 ^ t329;
    let t342 = t148 ^ t178;
    let t343 = t146 ^ t151;
    let t344 = t143 ^ t343;
    let t345 = t136 ^ t320;
    let t346 = t134 ^ t344;
    let t347 = t133 ^ t166;
    let t348 = t13 ^ t17;
    let t349 = t127 ^ t346;
    let t350 = t122 ^ t330;
    let t351 = t119 ^ t314;
    let t352 = t117 ^ t350;
    let t353 = t113 ^ t310;
    let t354 = t112 ^ t339;
    let t355 = t110 ^ t213;
    let t356 = t106 ^ t28;
    let t357 = t10 ^ t69;
    let t358 = t63 ^ t91;
    let t359 = t37 ^ t74;
    let t360 = t357 ^ t83;
    let t361 = t354 ^ t355;
    let t362 = t353 ^ t64;
    let t363 = t351 ^ t79;
    let t364 = t348 ^ t356;
    let t365 = t347 ^ t349;
    let t366 = t341 ^ t352;
    let t367 = t338 ^ t342;
    let t368 = t335 ^ t345;
    let t369 = t333 ^ t81;
    let t370 = t328 ^ t369;
    let t371 = t327 ^ t95;
    let t372 = t326 ^ t56;
    let t373 = t322 ^ t359;
    let t374 = t321 ^ t367;
    let t375 = t317 ^ t373;
    let t376 = t315 ^ t363;
    let t377 = t309 ^ t323;
    let t378 = t308 ^ t368;
    let t379 = t305 ^ t372;
    let t380 = t303 ^ t379;
    let t381 = t302 ^ t375;
    let t382 = t30 ^ t358;
    let t383 = t241 ^ t242;
    let t384 = t239 ^ t383;
    let t385 = t231 ^ t384;
    let t386 = t225 ^ t337;
    let t387 = t214 ^ t222;
    let t388 = t210 ^ t387;
    let t389 = t209 ^ t378;
    let t390 = t205 ^ t389;
    let t391 = t201 ^ t390;
    let t392 = t200 ^ t340;
    let t393 = t191 ^ t196;
    let t394 = t188 ^ t211;
    let t395 = t186 ^ t391;
    let t396 = t185 ^ t374;
    let t397 = t182 ^ t395;
    let t398 = t181 ^ t396;
    let t399 = t162 ^ t385;
    let t400 = t161 ^ t386;
    let t401 = t160 ^ t365;
    let t402 = t152 ^ t164;
    let t403 = t145 ^ t165;
    let t404 = t144 ^ t157;
    let t405 = t140 ^ t153;
    let t406 = t14 ^ t400;
    let t407 = t138 ^ t403;
    let t408 = t135 ^ t364;
    let t409 = t132 ^ t401;
    let t410 = t130 ^ t407;
    let t411 = t126 ^ t399;
    let t412 = t121 ^ t380;
    let t413 = t118 ^ t371;
    let t414 = t109 ^ t19;
    let t415 = t100 ^ t412;
    let t416 = bits[6] ^ t184;
    let t417 = bits[4] ^ t230;
    let t418 = bits[0] ^ t417;
    let t419 = t67 ^ t9;
    let t420 = t6 ^ t98;
    let t421 = t414 ^ t420;
    let t422 = t413 ^ t421;
    let t423 = t411 ^ t418;
    let t424 = t409 ^ t416;
    let t425 = t406 ^ t423;
    let t426 = t404 ^ t410;
    let t427 = t398 ^ t415;
    let t428 = t394 ^ t424;
    let t429 = t393 ^ t425;
    let t430 = t392 ^ t408;
    let t431 = t388 ^ t405;
    let t432 = t382 ^ t62;
    let t433 = t381 ^ t432;
    let t434 = t377 ^ t433;
    let t435 = t376 ^ t402;
    let t436 = t366 ^ t419;
    let t437 = t362 ^ t422;
    let t438 = t361 ^ t431;
    let t439 = t360 ^ t370;
    let t440 = t27 ^ t436;
    let t441 = t243 ^ t429;
    let t442 = t236 ^ t240;
    let t443 = t234 ^ t237;
    let t444 = t228 ^ t229;
    let t445 = t227 ^ t444;
    let t446 = t226 ^ t445;
    let t447 = t224 ^ t438;
    let t448 = t223 ^ t447;
    let t449 = t22 ^ t440;
    let t450 = t219 ^ t220;
    let t451 = t217 ^ t430;
    let t452 = t215 ^ t221;
    let t453 = t204 ^ t427;
    let t454 = t2 ^ t453;
    let t455 = t199 ^ t454;
    let t456 = t194 ^ t397;
    let t457 = t183 ^ t428;
    let t458 = t167 ^ t426;
    let t459 = t158 ^ t179;
    let t460 = t131 ^ t172;
    let t461 = t125 ^ t449;
    let t462 = t120 ^ t437;
    let t463 = t116 ^ t443;
    let t464 = bits[7] ^ t439;
    let t465 = bits[5] ^ t435;
    let t466 = bits[2] ^ t461;
    let t467 = bits[1] ^ t458;
    let t468 = t110 ^ t112;
    let t469 = t468 ^ t116;
    let t470 = t469 ^ t126;
    let t471 = t470 ^ t127;
    let t472 = t471 ^ t308;
    let t473 = t472 ^ t33;
    let t474 = t473 ^ t356;
    let t475 = t474 ^ t376;
    let t476 = t475 ^ t415;
    let t477 = t476 ^ t434;
    let t478 = t477 ^ t462;
    let t479 = t478 ^ t464;
    let t480 = t479 ^ t466;
    let t481 = bits[4] ^ t121;
    let t482 = t481 ^ t135;
    let t483 = t482 ^ t161;
    let t484 = t483 ^ t162;
    let t485 = t484 ^ t169;
    let t486 = t485 ^ t175;
    let t487 = t486 ^ t177;
    let t488 = t487 ^ t272;
    let t489 = t488 ^ t286;
    let t490 = t489 ^ t327;
    let t491 = t490 ^ t340;
    let t492 = t491 ^ t342;
    let t493 = t492 ^ t345;
    let t494 = t493 ^ t366;
    let t495 = t494 ^ t381;
    let t496 = t495 ^ t402;
    let t497 = t496 ^ t405;
    let t498 = t497 ^ t409;
    let t499 = t498 ^ t45;
    let t500 = t499 ^ t459;
    let t501 = t500 ^ t460;
    let t502 = t501 ^ t464;
    let t503 = t502 ^ t467;
    let t504 = t503 ^ t72;
    let t505 = t123 ^ t16;
    let t506 = t505 ^ t177;
    let t507 = t506 ^ t200;
    let t508 = t507 ^ t210;
    let t509 = t508 ^ t248;
    let t510 = t509 ^ t258;
    let t511 = t510 ^ t271;
    let t512 = t511 ^ t278;
    let t513 = t512 ^ t289;
    let t514 = t513 ^ t309;
    let t515 = t514 ^ t337;
    let t516 = t515 ^ t34;
    let t517 = t516 ^ t348;
    let t518 = t517 ^ t354;
    let t519 = t518 ^ t360;
    let t520 = t519 ^ t362;
    let t521 = t520 ^ t393;
    let t522 = t521 ^ t410;
    let t523 = t522 ^ t455;
    let t524 = t523 ^ t456;
    let t525 = t524 ^ t457;
    let t526 = t525 ^ t465;
    let t527 = t526 ^ t51;
    let t528 = t527 ^ t61;
    let t529 = t100 ^ t11;
    let t530 = t529 ^ t138;
    let t531 = t530 ^ t148;
    let t532 = t531 ^ t216;
    let t533 = t532 ^ t218;
    let t534 = t533 ^ t252;
    let t535 = t534 ^ t255;
    let t536 = t535 ^ t261;
    let t537 = t536 ^ t262;
    let t538 = t537 ^ t264;
    let t539 = t538 ^ t280;
    let t540 = t539 ^ t283;
    let t541 = t540 ^ t317;
    let t542 = t541 ^ t328;
    let t543 = t542 ^ t335;
    let t544 = t543 ^ t351;
    let t545 = t544 ^ t353;
    let t546 = t545 ^ t377;
    let t547 = t546 ^ t406;
    let t548 = t547 ^ t448;
    let t549 = t548 ^ t450;
    let t550 = t549 ^ t451;
    let t551 = t550 ^ t452;
    let t552 = t551 ^ t457;
    let t553 = t552 ^ t460;
    let t554 = t553 ^ t466;
    let t555 = bits[1] ^ bits[7];
    let t556 = t555 ^ t1;
    let t557 = t556 ^ t108;
    let t558 = t557 ^ t136;
    let t559 = t558 ^ t144;
    let t560 = t559 ^ t15;
    let t561 = t560 ^ t175;
    let t562 = t561 ^ t182;
    let t563 = t562 ^ t231;
    let t564 = t563 ^ t232;
    let t565 = t564 ^ t233;
    let t566 = t565 ^ t235;
    let t567 = t566 ^ t236;
    let t568 = t567 ^ t245;
    let t569 = t568 ^ t292;
    let t570 = t569 ^ t298;
    let t571 = t570 ^ t299;
    let t572 = t571 ^ t301;
    let t573 = t572 ^ t322;
    let t574 = t573 ^ t333;
    let t575 = t574 ^ t341;
    let t576 = t575 ^ t347;
    let t577 = t576 ^ t361;
    let t578 = t577 ^ t414;
    let t579 = t578 ^ t418;
    let t580 = t579 ^ t446;
    let t581 = t580 ^ t451;
    let t582 = t581 ^ t455;
    let t583 = t582 ^ t463;
    let t584 = t134 ^ t14;
    let t585 = t584 ^ t152;
    let t586 = t585 ^ t160;
    let t587 = t586 ^ t199;
    let t588 = t587 ^ t238;
    let t589 = t588 ^ t246;
    let t590 = t589 ^ t266;
    let t591 = t590 ^ t277;
    let t592 = t591 ^ t282;
    let t593 = t592 ^ t288;
    let t594 = t593 ^ t290;
    let t595 = t594 ^ t300;
    let t596 = t595 ^ t305;
    let t597 = t596 ^ t31;
    let t598 = t597 ^ t315;
    let t599 = t598 ^ t338;
    let t600 = t599 ^ t357;
    let t601 = t600 ^ t397;
    let t602 = t601 ^ t404;
    let t603 = t602 ^ t411;
    let t604 = t603 ^ t416;
    let t605 = t604 ^ t434;
    let t606 = t605 ^ t442;
    let t607 = t606 ^ t446;
    let t608 = t607 ^ t448;
    let t609 = t106 ^ t143;
    let t610 = t609 ^ t203;
    let t611 = t610 ^ t204;
    let t612 = t611 ^ t223;
    let t613 = t612 ^ t247;
    let t614 = t613 ^ t25;
    let t615 = t614 ^ t259;
    let t616 = t615 ^ t275;
    let t617 = t616 ^ t279;
    let t618 = t617 ^ t296;
    let t619 = t618 ^ t321;
    let t620 = t619 ^ t326;
    let t621 = t620 ^ t352;
    let t622 = t621 ^ t355;
    let t623 = t622 ^ t382;
    let t624 = t623 ^ t392;
    let t625 = t624 ^ t394;
    let t626 = t625 ^ t42;
    let t627 = t626 ^ t441;
    let t628 = t627 ^ t452;
    let t629 = t628 ^ t456;
    let t630 = t629 ^ t462;
    let t631 = t630 ^ t467;
    let t632 = t0 ^ t10;
    let t633 = t632 ^ t139;
    let t634 = t633 ^ t141;
    let t635 = t634 ^ t205;
    let t636 = t635 ^ t21;
    let t637 = t636 ^ t244;
    let t638 = t637 ^ t251;
    let t639 = t638 ^ t256;
    let t640 = t639 ^ t265;
    let t641 = t640 ^ t27;
    let t642 = t641 ^ t294;
    let t643 = t642 ^ t302;
    let t644 = t643 ^ t303;
    let t645 = t644 ^ t323;
    let t646 = t645 ^ t33;
    let t647 = t646 ^ t349;
    let t648 = t647 ^ t370;
    let t649 = t648 ^ t388;
    let t650 = t649 ^ t398;
    let t651 = t650 ^ t408;
    let t652 = t651 ^ t413;
    let t653 = t652 ^ t441;
    let t654 = t653 ^ t442;
    let t655 = t654 ^ t450;
    let t656 = t655 ^ t459;
    let t657 = t656 ^ t463;
    let t658 = t657 ^ t465;
    let t659 = !t504;
    let t660 = !t554;
    let t661 = !t583;
    let t662 = !t608;
    [t480, t659, t528, t660, t661, t662, t631, t658]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rustfmt::skip]
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

    #[rustfmt::skip]
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

    /// Exhaustively verify the generated circuit against the original table.
    /// Each logical bit is broadcast to all 8 lanes of a `u8` word (0x00 = false,
    /// 0xFF = true) so that `!` behaves as a per-lane NOT, matching bitslice usage.
    #[test]
    fn block_sbox_matches_table() {
        for x in 0u32 .. 256 {
            let mut bits = [0u8; 8];
            for i in 0 .. 8 {
                bits[i] = if (x >> i) & 1 == 1 { 0xFF } else { 0x00 };
            }
            let out = block_sbox(bits);
            let mut y = 0u32;
            for o in 0 .. 8 {
                // every lane is identical; take lane 0.
                assert!(out[o] == 0x00 || out[o] == 0xFF, "non-uniform lane");
                y |= ((out[o] & 1) as u32) << o;
            }
            assert_eq!(y, BLOCK_SBOX[x as usize] as u32, "mismatch at x={x:#04x}");
        }
    }

    /// Verify that `BLOCK_PERM_BITS` reproduces the `BLOCK_PERM` table exactly:
    /// moving each input bit `i` to position `BLOCK_PERM_BITS[i]`.
    #[test]
    fn block_perm_bits_matches_table() {
        for v in 0usize .. 256 {
            let mut permuted = 0u8;
            for i in 0 .. 8 {
                if (v >> i) & 1 == 1 {
                    permuted |= 1 << BLOCK_PERM_BITS[i];
                }
            }
            assert_eq!(permuted, BLOCK_PERM[v], "perm mismatch at v={v:#04x}");
        }
    }
}
