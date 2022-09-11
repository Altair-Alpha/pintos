#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

static int f = 16384; // f value for 17.14 fixed point
typedef int fixed_point;

static inline fixed_point itof(int n) {
  return n * f;
}

static inline int ftoi(fixed_point x) {
  return x / f;
}

static inline int ftoi_round(fixed_point x) {
  return x >= 0 ? (x + f / 2) / f : (x - f / 2) / f;
}

// fixed_point add_ff(fixed_point x, fixed_point y) {
//     return x + y;
// }

static inline fixed_point add_fi(fixed_point x, int n) {
  return x + n * f;
}

// fixed_point sub_ff(fixed_point x, fixed_point y) {
//     return x - y;
// }

static inline fixed_point sub_fi(fixed_point x, int n) {
  return x - n * f;
}

static inline fixed_point mul_ff(fixed_point x, fixed_point y) {
  return ((int64_t)x) * y / f;
}

// fixed_point mul_fi(fixed_point x, int n) {
//   return x * n;
// }

static inline fixed_point div_ff(fixed_point x, fixed_point y) {
  return ((int64_t)x) * f / y;
}

// fixed_point div_fi(fixed_point x, int n) {
//   return x / n;
// }

#endif /**< threads/fixed_point.h */