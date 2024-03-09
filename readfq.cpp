#include <unistd.h>
#include <sys/stat.h>

#include <float.h>
#include "city.h"
#include "readfq.h"
#include <algorithm>
#include <cstring>  // for memcpy and memset

using namespace std;

static uint64 UNALIGNED_LOAD64(const char *p) {
  uint64 result;
  memcpy(&result, p, sizeof(result));
  return result;
}

static uint32 UNALIGNED_LOAD32(const char *p) {
  uint32 result;
  memcpy(&result, p, sizeof(result));
  return result;
}

#ifdef _MSC_VER

#include <stdlib.h>
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)

#elif defined(__APPLE__)

// Mac OS X / Darwin features
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#elif defined(__FreeBSD__)

#include <sys/endian.h>
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)

#elif defined(__NetBSD__)

#include <sys/types.h>
#include <machine/bswap.h>
#if defined(__BSWAP_RENAME) && !defined(__bswap_32)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif

#else

#include <byteswap.h>

#endif

#ifdef WORDS_BIGENDIAN
#define uint32_in_expected_order(x) (bswap_32(x))
#define uint64_in_expected_order(x) (bswap_64(x))
#else
#define uint32_in_expected_order(x) (x)
#define uint64_in_expected_order(x) (x)
#endif

#if !defined(LIKELY)
#if HAVE_BUILTIN_EXPECT
#define LIKELY(x) (__builtin_expect(!!(x), 1))
#else
#define LIKELY(x) (x)
#endif
#endif

static uint64 Fetch64(const char *p) {
  return uint64_in_expected_order(UNALIGNED_LOAD64(p));
}

static uint32 Fetch32(const char *p) {
  return uint32_in_expected_order(UNALIGNED_LOAD32(p));
}

// Some primes between 2^63 and 2^64 for various uses.
static const uint64 k0 = 0xc3a5c85c97cb3127ULL;
static const uint64 k1 = 0xb492b66fbe98f273ULL;
static const uint64 k2 = 0x9ae16a3b2f90404fULL;

// Magic numbers for 32-bit hashing.  Copied from Murmur3.
static const uint32_t c1 = 0xcc9e2d51;
static const uint32_t c2 = 0x1b873593;

// A 32-bit to 32-bit integer hash copied from Murmur3.
static uint32 fmix(uint32 h)
{
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

static uint32 Rotate32(uint32 val, int shift) {
  // Avoid shifting by 32: doing so yields an undefined result.
  return shift == 0 ? val : ((val >> shift) | (val << (32 - shift)));
}

#undef PERMUTE3
#define PERMUTE3(a, b, c) do { std::swap(a, b); std::swap(a, c); } while (0)

static uint32 Mur(uint32 a, uint32 h) {
  // Helper from Murmur3 for combining two 32-bit values.
  a *= c1;
  a = Rotate32(a, 17);
  a *= c2;
  h ^= a;
  h = Rotate32(h, 19);
  return h * 5 + 0xe6546b64;
}

static uint32 Hash32Len13to24(const char *s, size_t len) {
  uint32 a = Fetch32(s - 4 + (len >> 1));
  uint32 b = Fetch32(s + 4);
  uint32 c = Fetch32(s + len - 8);
  uint32 d = Fetch32(s + (len >> 1));
  uint32 e = Fetch32(s);
  uint32 f = Fetch32(s + len - 4);
  uint32 h = len;

  return fmix(Mur(f, Mur(e, Mur(d, Mur(c, Mur(b, Mur(a, h)))))));
}

static uint32 Hash32Len0to4(const char *s, size_t len) {
  uint32 b = 0;
  uint32 c = 9;
  for (int i = 0; i < len; i++) {
    signed char v = s[i];
    b = b * c1 + v;
    c ^= b;
  }
  return fmix(Mur(b, Mur(len, c)));
}

static uint32 Hash32Len5to12(const char *s, size_t len) {
  uint32 a = len, b = len * 5, c = 9, d = b;
  a += Fetch32(s);
  b += Fetch32(s + len - 4);
  c += Fetch32(s + ((len >> 1) & 4));
  return fmix(Mur(c, Mur(b, Mur(a, d))));
}

uint32 CityHash32(const char *s, size_t len) {
  if (len <= 24) {
    return len <= 12 ?
        (len <= 4 ? Hash32Len0to4(s, len) : Hash32Len5to12(s, len)) :
        Hash32Len13to24(s, len);
  }

  // len > 24
  uint32 h = len, g = c1 * len, f = g;
  uint32 a0 = Rotate32(Fetch32(s + len - 4) * c1, 17) * c2;
  uint32 a1 = Rotate32(Fetch32(s + len - 8) * c1, 17) * c2;
  uint32 a2 = Rotate32(Fetch32(s + len - 16) * c1, 17) * c2;
  uint32 a3 = Rotate32(Fetch32(s + len - 12) * c1, 17) * c2;
  uint32 a4 = Rotate32(Fetch32(s + len - 20) * c1, 17) * c2;
  h ^= a0;
  h = Rotate32(h, 19);
  h = h * 5 + 0xe6546b64;
  h ^= a2;
  h = Rotate32(h, 19);
  h = h * 5 + 0xe6546b64;
  g ^= a1;
  g = Rotate32(g, 19);
  g = g * 5 + 0xe6546b64;
  g ^= a3;
  g = Rotate32(g, 19);
  g = g * 5 + 0xe6546b64;
  f += a4;
  f = Rotate32(f, 19);
  f = f * 5 + 0xe6546b64;
  size_t iters = (len - 1) / 20;
  do {
    uint32 a0 = Rotate32(Fetch32(s) * c1, 17) * c2;
    uint32 a1 = Fetch32(s + 4);
    uint32 a2 = Rotate32(Fetch32(s + 8) * c1, 17) * c2;
    uint32 a3 = Rotate32(Fetch32(s + 12) * c1, 17) * c2;
    uint32 a4 = Fetch32(s + 16);
    h ^= a0;
    h = Rotate32(h, 18);
    h = h * 5 + 0xe6546b64;
    f += a1;
    f = Rotate32(f, 19);
    f = f * c1;
    g += a2;
    g = Rotate32(g, 18);
    g = g * 5 + 0xe6546b64;
    h ^= a3 + a1;
    h = Rotate32(h, 19);
    h = h * 5 + 0xe6546b64;
    g ^= a4;
    g = bswap_32(g) * 5;
    h += a4 * 5;
    h = bswap_32(h);
    f += a0;
    PERMUTE3(f, h, g);
    s += 20;
  } while (--iters != 0);
  g = Rotate32(g, 11) * c1;
  g = Rotate32(g, 17) * c1;
  f = Rotate32(f, 11) * c1;
  f = Rotate32(f, 17) * c1;
  h = Rotate32(h + g, 19);
  h = h * 5 + 0xe6546b64;
  h = Rotate32(h, 17) * c1;
  h = Rotate32(h + f, 19);
  h = h * 5 + 0xe6546b64;
  h = Rotate32(h, 17) * c1;
  return h;
}

// Bitwise right rotate.  Normally this will compile to a single
// instruction, especially if the shift is a manifest constant.
static uint64 Rotate(uint64 val, int shift) {
  // Avoid shifting by 64: doing so yields an undefined result.
  return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
}

static uint64 ShiftMix(uint64 val) {
  return val ^ (val >> 47);
}

static uint64 HashLen16(uint64 u, uint64 v) {
  return Hash128to64(uint128(u, v));
}

static uint64 HashLen16(uint64 u, uint64 v, uint64 mul) {
  // Murmur-inspired hashing.
  uint64 a = (u ^ v) * mul;
  a ^= (a >> 47);
  uint64 b = (v ^ a) * mul;
  b ^= (b >> 47);
  b *= mul;
  return b;
}

static uint64 HashLen0to16(const char *s, size_t len) {
  if (len >= 8) {
    uint64 mul = k2 + len * 2;
    uint64 a = Fetch64(s) + k2;
    uint64 b = Fetch64(s + len - 8);
    uint64 c = Rotate(b, 37) * mul + a;
    uint64 d = (Rotate(a, 25) + b) * mul;
    return HashLen16(c, d, mul);
  }
  if (len >= 4) {
    uint64 mul = k2 + len * 2;
    uint64 a = Fetch32(s);
    return HashLen16(len + (a << 3), Fetch32(s + len - 4), mul);
  }
  if (len > 0) {
    uint8 a = s[0];
    uint8 b = s[len >> 1];
    uint8 c = s[len - 1];
    uint32 y = static_cast<uint32>(a) + (static_cast<uint32>(b) << 8);
    uint32 z = len + (static_cast<uint32>(c) << 2);
    return ShiftMix(y * k2 ^ z * k0) * k2;
  }
  return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
static uint64 HashLen17to32(const char *s, size_t len) {
  uint64 mul = k2 + len * 2;
  uint64 a = Fetch64(s) * k1;
  uint64 b = Fetch64(s + 8);
  uint64 c = Fetch64(s + len - 8) * mul;
  uint64 d = Fetch64(s + len - 16) * k2;
  return HashLen16(Rotate(a + b, 43) + Rotate(c, 30) + d,
                   a + Rotate(b + k2, 18) + c, mul);
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
static pair<uint64, uint64> WeakHashLen32WithSeeds(
    uint64 w, uint64 x, uint64 y, uint64 z, uint64 a, uint64 b) {
  a += w;
  b = Rotate(b + a + z, 21);
  uint64 c = a;
  a += x;
  a += y;
  b += Rotate(a, 44);
  return make_pair(a + z, b + c);
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
static pair<uint64, uint64> WeakHashLen32WithSeeds(
    const char* s, uint64 a, uint64 b) {
  return WeakHashLen32WithSeeds(Fetch64(s),
                                Fetch64(s + 8),
                                Fetch64(s + 16),
                                Fetch64(s + 24),
                                a,
                                b);
}

// Return an 8-byte hash for 33 to 64 bytes.
static uint64 HashLen33to64(const char *s, size_t len) {
  uint64 mul = k2 + len * 2;
  uint64 a = Fetch64(s) * k2;
  uint64 b = Fetch64(s + 8);
  uint64 c = Fetch64(s + len - 24);
  uint64 d = Fetch64(s + len - 32);
  uint64 e = Fetch64(s + 16) * k2;
  uint64 f = Fetch64(s + 24) * 9;
  uint64 g = Fetch64(s + len - 8);
  uint64 h = Fetch64(s + len - 16) * mul;
  uint64 u = Rotate(a + g, 43) + (Rotate(b, 30) + c) * 9;
  uint64 v = ((a + g) ^ d) + f + 1;
  uint64 w = bswap_64((u + v) * mul) + h;
  uint64 x = Rotate(e + f, 42) + c;
  uint64 y = (bswap_64((v + w) * mul) + g) * mul;
  uint64 z = e + f + c;
  a = bswap_64((x + z) * mul + y) + b;
  b = ShiftMix((z + a) * mul + d + h) * mul;
  return b + x;
}

uint64 CityHash64(const char *s, size_t len) {
  if (len <= 32) {
    if (len <= 16) {
      return HashLen0to16(s, len);
    } else {
      return HashLen17to32(s, len);
    }
  } else if (len <= 64) {
    return HashLen33to64(s, len);
  }

  // For strings over 64 bytes we hash the end first, and then as we
  // loop we keep 56 bytes of state: v, w, x, y, and z.
  uint64 x = Fetch64(s + len - 40);
  uint64 y = Fetch64(s + len - 16) + Fetch64(s + len - 56);
  uint64 z = HashLen16(Fetch64(s + len - 48) + len, Fetch64(s + len - 24));
  pair<uint64, uint64> v = WeakHashLen32WithSeeds(s + len - 64, len, z);
  pair<uint64, uint64> w = WeakHashLen32WithSeeds(s + len - 32, y + k1, x);
  x = x * k1 + Fetch64(s);

  // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
  len = (len - 1) & ~static_cast<size_t>(63);
  do {
    x = Rotate(x + y + v.first + Fetch64(s + 8), 37) * k1;
    y = Rotate(y + v.second + Fetch64(s + 48), 42) * k1;
    x ^= w.second;
    y += v.first + Fetch64(s + 40);
    z = Rotate(z + w.first, 33) * k1;
    v = WeakHashLen32WithSeeds(s, v.second * k1, x + w.first);
    w = WeakHashLen32WithSeeds(s + 32, z + w.second, y + Fetch64(s + 16));
    std::swap(z, x);
    s += 64;
    len -= 64;
  } while (len != 0);
  return HashLen16(HashLen16(v.first, w.first) + ShiftMix(y) * k1 + z,
                   HashLen16(v.second, w.second) + x);
}

uint64 CityHash64WithSeed(const char *s, size_t len, uint64 seed) {
  return CityHash64WithSeeds(s, len, k2, seed);
}

uint64 CityHash64WithSeeds(const char *s, size_t len,
                           uint64 seed0, uint64 seed1) {
  return HashLen16(CityHash64(s, len) - seed0, seed1);
}

// A subroutine for CityHash128().  Returns a decent 128-bit hash for strings
// of any length representable in signed long.  Based on City and Murmur.
static uint128 CityMurmur(const char *s, size_t len, uint128 seed) {
  uint64 a = Uint128Low64(seed);
  uint64 b = Uint128High64(seed);
  uint64 c = 0;
  uint64 d = 0;
  signed long l = len - 16;
  if (l <= 0) {  // len <= 16
    a = ShiftMix(a * k1) * k1;
    c = b * k1 + HashLen0to16(s, len);
    d = ShiftMix(a + (len >= 8 ? Fetch64(s) : c));
  } else {  // len > 16
    c = HashLen16(Fetch64(s + len - 8) + k1, a);
    d = HashLen16(b + len, c + Fetch64(s + len - 16));
    a += d;
    do {
      a ^= ShiftMix(Fetch64(s) * k1) * k1;
      a *= k1;
      b ^= a;
      c ^= ShiftMix(Fetch64(s + 8) * k1) * k1;
      c *= k1;
      d ^= c;
      s += 16;
      l -= 16;
    } while (l > 0);
  }
  a = HashLen16(a, c);
  b = HashLen16(d, b);
  return uint128(a ^ b, HashLen16(b, a));
}

uint128 CityHash128WithSeed(const char *s, size_t len, uint128 seed) {
  if (len < 128) {
    return CityMurmur(s, len, seed);
  }

  // We expect len >= 128 to be the common case.  Keep 56 bytes of state:
  // v, w, x, y, and z.
  pair<uint64, uint64> v, w;
  uint64 x = Uint128Low64(seed);
  uint64 y = Uint128High64(seed);
  uint64 z = len * k1;
  v.first = Rotate(y ^ k1, 49) * k1 + Fetch64(s);
  v.second = Rotate(v.first, 42) * k1 + Fetch64(s + 8);
  w.first = Rotate(y + z, 35) * k1 + x;
  w.second = Rotate(x + Fetch64(s + 88), 53) * k1;

  // This is the same inner loop as CityHash64(), manually unrolled.
  do {
    x = Rotate(x + y + v.first + Fetch64(s + 8), 37) * k1;
    y = Rotate(y + v.second + Fetch64(s + 48), 42) * k1;
    x ^= w.second;
    y += v.first + Fetch64(s + 40);
    z = Rotate(z + w.first, 33) * k1;
    v = WeakHashLen32WithSeeds(s, v.second * k1, x + w.first);
    w = WeakHashLen32WithSeeds(s + 32, z + w.second, y + Fetch64(s + 16));
    std::swap(z, x);
    s += 64;
    x = Rotate(x + y + v.first + Fetch64(s + 8), 37) * k1;
    y = Rotate(y + v.second + Fetch64(s + 48), 42) * k1;
    x ^= w.second;
    y += v.first + Fetch64(s + 40);
    z = Rotate(z + w.first, 33) * k1;
    v = WeakHashLen32WithSeeds(s, v.second * k1, x + w.first);
    w = WeakHashLen32WithSeeds(s + 32, z + w.second, y + Fetch64(s + 16));
    std::swap(z, x);
    s += 64;
    len -= 128;
  } while (LIKELY(len >= 128));
  x += Rotate(v.first + z, 49) * k0;
  y = y * k0 + Rotate(w.second, 37);
  z = z * k0 + Rotate(w.first, 27);
  w.first *= 9;
  v.first *= k0;
  // If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
  for (size_t tail_done = 0; tail_done < len; ) {
    tail_done += 32;
    y = Rotate(x + y, 42) * k0 + v.second;
    w.first += Fetch64(s + len - tail_done + 16);
    x = x * k0 + w.first;
    z += w.second + Fetch64(s + len - tail_done);
    w.second += v.first;
    v = WeakHashLen32WithSeeds(s + len - tail_done, v.first + z, v.second);
    v.first *= k0;
  }
  // At this point our 56 bytes of state should contain more than
  // enough information for a strong 128-bit hash.  We use two
  // different 56-byte-to-8-byte hashes to get a 16-byte final result.
  x = HashLen16(x, v.first);
  y = HashLen16(y + z, w.first);
  return uint128(HashLen16(x + v.second, w.second) + y,
                 HashLen16(x + w.second, y + v.second));
}

uint128 CityHash128(const char *s, size_t len) {
  return len >= 16 ?
      CityHash128WithSeed(s + 16, len - 16,
                          uint128(Fetch64(s), Fetch64(s + 8) + k0)) :
      CityHash128WithSeed(s, len, uint128(k0, k1));
}

#ifdef __SSE4_2__
#include <citycrc.h>
#include <nmmintrin.h>

// Requires len >= 240.
static void CityHashCrc256Long(const char *s, size_t len,
                               uint32 seed, uint64 *result) {
  uint64 a = Fetch64(s + 56) + k0;
  uint64 b = Fetch64(s + 96) + k0;
  uint64 c = result[0] = HashLen16(b, len);
  uint64 d = result[1] = Fetch64(s + 120) * k0 + len;
  uint64 e = Fetch64(s + 184) + seed;
  uint64 f = 0;
  uint64 g = 0;
  uint64 h = c + d;
  uint64 x = seed;
  uint64 y = 0;
  uint64 z = 0;

  // 240 bytes of input per iter.
  size_t iters = len / 240;
  len -= iters * 240;
  do {
#undef CHUNK
#define CHUNK(r)                                \
    PERMUTE3(x, z, y);                          \
    b += Fetch64(s);                            \
    c += Fetch64(s + 8);                        \
    d += Fetch64(s + 16);                       \
    e += Fetch64(s + 24);                       \
    f += Fetch64(s + 32);                       \
    a += b;                                     \
    h += f;                                     \
    b += c;                                     \
    f += d;                                     \
    g += e;                                     \
    e += z;                                     \
    g += x;                                     \
    z = _mm_crc32_u64(z, b + g);                \
    y = _mm_crc32_u64(y, e + h);                \
    x = _mm_crc32_u64(x, f + a);                \
    e = Rotate(e, r);                           \
    c += e;                                     \
    s += 40

    CHUNK(0); PERMUTE3(a, h, c);
    CHUNK(33); PERMUTE3(a, h, f);
    CHUNK(0); PERMUTE3(b, h, f);
    CHUNK(42); PERMUTE3(b, h, d);
    CHUNK(0); PERMUTE3(b, h, e);
    CHUNK(33); PERMUTE3(a, h, e);
  } while (--iters > 0);

  while (len >= 40) {
    CHUNK(29);
    e ^= Rotate(a, 20);
    h += Rotate(b, 30);
    g ^= Rotate(c, 40);
    f += Rotate(d, 34);
    PERMUTE3(c, h, g);
    len -= 40;
  }
  if (len > 0) {
    s = s + len - 40;
    CHUNK(33);
    e ^= Rotate(a, 43);
    h += Rotate(b, 42);
    g ^= Rotate(c, 41);
    f += Rotate(d, 40);
  }
  result[0] ^= h;
  result[1] ^= g;
  g += h;
  a = HashLen16(a, g + z);
  x += y << 32;
  b += x;
  c = HashLen16(c, z) + h;
  d = HashLen16(d, e + result[0]);
  g += e;
  h += HashLen16(x, f);
  e = HashLen16(a, d) + g;
  z = HashLen16(b, c) + a;
  y = HashLen16(g, h) + c;
  result[0] = e + z + y + x;
  a = ShiftMix((a + y) * k0) * k0 + b;
  result[1] += a + result[0];
  a = ShiftMix(a * k0) * k0 + c;
  result[2] = a + result[1];
  a = ShiftMix((a + e) * k0) * k0;
  result[3] = a + result[2];
}

// Requires len < 240.
static void CityHashCrc256Short(const char *s, size_t len, uint64 *result) {
  char buf[240];
  memcpy(buf, s, len);
  memset(buf + len, 0, 240 - len);
  CityHashCrc256Long(buf, 240, ~static_cast<uint32>(len), result);
}

void CityHashCrc256(const char *s, size_t len, uint64 *result) {
  if (LIKELY(len >= 240)) {
    CityHashCrc256Long(s, len, 0, result);
  } else {
    CityHashCrc256Short(s, len, result);
  }
}

uint128 CityHashCrc128WithSeed(const char *s, size_t len, uint128 seed) {
  if (len <= 900) {
    return CityHash128WithSeed(s, len, seed);
  } else {
    uint64 result[4];
    CityHashCrc256(s, len, result);
    uint64 u = Uint128High64(seed) + result[0];
    uint64 v = Uint128Low64(seed) + result[1];
    return uint128(HashLen16(u, v + result[2]),
                   HashLen16(Rotate(v, 32), u * k0 + result[3]));
  }
}

uint128 CityHashCrc128(const char *s, size_t len) {
  if (len <= 900) {
    return CityHash128(s, len);
  } else {
    uint64 result[4];
    CityHashCrc256(s, len, result);
    return uint128(result[2], result[3]);
  }
}

#endif



bool  opt_fastqout = 1;

const unsigned char chrmap_upcase[256] =
{
    /*

      Map from ascii to ascii
      Convert to upper case nucleotide

     @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
     P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    */

    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',

    'N','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
    'P','Q','R','S','T','U','V','W','X','Y','Z','N','N','N','N','N',
    'N','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
    'P','Q','R','S','T','U','V','W','X','Y','Z','N','N','N','N','N',

    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',

    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N'
};



#define FASTX_BUFFER_ALLOC 8192

#define __stat64 _stat64 // For legacy compatibility
typedef struct __stat64 xstat_t;




unsigned int char_header_action[256] =
{
    /*
      FASTA/FASTQ header characters
      0 = null
      1 = legal, printable ascii
      2 = illegal, fatal
      3 = cr
      4 = lf
      5 = tab
      6 = space
      7 = non-ascii, legal, but warn
    @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
    P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    */

    0,  2,  2,  2,  2,  2,  2,  2,  2,  5,  4,  2,  2,  3,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    6,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  2,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7
};




unsigned int char_fq_action_seq[256] =
{
    /*
      How to handle input characters for FASTQ:
      All IUPAC characters are valid.
      CR (^M) silently stripped.
      LF is newline.
      Rest is fatal
      0=stripped, 1=legal, 2=fatal, 3=silently stripped, 4=newline
    @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
    P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    */

    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  4,  2,  2,  3,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  1,  1,  1,  1,  2,  2,  1,  1,  2,  2,  1,  2,  1,  1,  2,
    2,  2,  1,  1,  1,  1,  1,  1,  2,  1,  2,  2,  2,  2,  2,  2,
    2,  1,  1,  1,  1,  2,  2,  1,  1,  2,  2,  1,  2,  1,  1,  2,
    2,  2,  1,  1,  1,  1,  1,  1,  2,  1,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
};

unsigned int char_fq_action_qual[256] =
{
    /*
    Quality characters, any from 33 to 126 is valid.
    CR (^M) silently stripped.
    LF is newline.
    Rest is fatal
    @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
    P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    */

    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  4,  2,  2,  3,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2
};

const unsigned char chrmap_identity[256] =
{
    /* identity map */

    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,

    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,

    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,

    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,

    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,

    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,

    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,

    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,

    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,

    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,

    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,

    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,

    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,

    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,

    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,

    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};





unsigned int chrmap_2bit[256] =
{
    /*
       Map from ascii to 2-bit nucleotide code
       Aa: 0
       Cc: 1
       Gg: 2
       TtUu: 3
       All others: 0
    @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
    P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    */

    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  1,  0,  0,  0,  2,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  3,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  1,  0,  0,  0,  2,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  3,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};

unsigned int chrmap_mask_ambig[256] =
{
    /*
      Should character be masked and not used for search ?
      Mask everything but A, C, G, T and U.
      Lower case letters are NOT masked.
     @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
     P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    */

     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  0,  1,  0,  1,  1,  1,  0,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  0,  0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  0,  1,  0,  1,  1,  1,  0,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  0,  0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1
};

const unsigned char chrmap_complement[256] =
{
    /*
      Map from ascii to ascii, complementary nucleotide
     @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
     P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    */

    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',

    'N','T','V','G','H','N','N','C','D','N','N','M','N','K','N','N',
    'N','N','Y','S','A','A','B','W','N','R','N','N','N','N','N','N',
    'N','t','v','g','h','N','N','c','d','N','N','m','N','k','n','N',
    'N','N','y','s','a','a','b','w','N','r','N','N','N','N','N','N',

    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',

    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N',
    'N','N','N','N','N','N','N','N','N','N','N','N','N','N','N','N'
};




void buffer_filter_extend(fastx_handle h,
    struct fastx_buffer_s* dest_buffer,
    char* source_buf,
    uint64_t len,
    unsigned int* char_action,
    const unsigned char* char_mapping,
    bool* ok,
    char* illegal_char)
{
    buffer_makespace(dest_buffer, len + 1);

    /* Strip unwanted characters from the string and raise warnings or
       errors on certain characters. */

    char* p = source_buf;
    char* d = dest_buffer->data + dest_buffer->length;
    char* q = d;
    *ok = true;

    for (uint64_t i = 0; i < len; i++)
    {
        char c = *p++;
        char m = char_action[(unsigned char)c];

        switch (m)
        {
        case 0:
            /* stripped */
            h->stripped_all++;
            h->stripped[(unsigned char)c]++;
            break;

        case 1:
            /* legal character */
            *q++ = char_mapping[(unsigned char)(c)];
            break;

        case 2:
            /* fatal character */
            if (*ok)
            {
                *illegal_char = c;
            }
            *ok = false;
            break;

        case 3:
            /* silently stripped chars (whitespace) */
            break;

        case 4:
            /* newline (silently stripped) */
            break;
        }
    }

    /* add zero after sequence */
    *q = 0;
    dest_buffer->length += q - d;
}


void fastx_filter_header(fastx_handle h, bool truncateatspace)
{
    /* filter and truncate header */

    char* p = h->header_buffer.data;
    char* q = p;

    while (true)
    {
        unsigned char c = *p++;
        unsigned int m = char_header_action[c];

        switch (m)
        {
        case 1:
            /* legal, printable character */
            *q++ = c;
            break;

        case 2:
            /* illegal, fatal */

            exit(EXIT_FAILURE);

        case 7:
            /* Non-ASCII but acceptable */


            *q++ = c;
            break;

        case 5:
        case 6:
            /* tab or space */
            /* conditional end of line */
            if (truncateatspace)
            {
                goto end_of_line;
            }

            *q++ = c;
            break;

        case 0:
            /* null */
        case 3:
            /* cr */
        case 4:
            /* lf */
            /* end of line */
            goto end_of_line;

        default:
            printf("Internal error");
            break;
        }
    }

end_of_line:
    /* add a null character at the end */
    *q = 0;
    h->header_buffer.length = q - h->header_buffer.data;
}

bool fastq_next(fastx_handle h,
    bool truncateatspace,
    const unsigned char* char_mapping)
{
    h->header_buffer.length = 0;
    h->header_buffer.data[0] = 0;
    h->sequence_buffer.length = 0;
    h->sequence_buffer.data[0] = 0;
    h->plusline_buffer.length = 0;
    h->plusline_buffer.data[0] = 0;
    h->quality_buffer.length = 0;
    h->quality_buffer.data[0] = 0;

    h->lineno_start = h->lineno;

    char msg[200];
    bool ok = true;
    char illegal_char = 0;

    uint64_t rest = fastx_file_fill_buffer(h);

    /* check end of file */

    if (rest == 0)
    {
        return false;
    }

    /* read header */

    /* check initial @ character */

    if (h->file_buffer.data[h->file_buffer.position] != '@')
    {
        printf("Header line must start with '@' character");
    }
    h->file_buffer.position++;
    rest--;

    char* lf = nullptr;
    while (lf == nullptr)
    {
        /* get more data if buffer empty */
        rest = fastx_file_fill_buffer(h);
        if (rest == 0)
        {
            printf("Unexpected end of file");
        }

        /* find LF */
        lf = (char*)memchr(h->file_buffer.data + h->file_buffer.position,
            '\n',
            rest);

        /* copy to header buffer */
        uint64_t len = rest;
        if (lf)
        {
            /* LF found, copy up to and including LF */
            len = lf - (h->file_buffer.data + h->file_buffer.position) + 1;
            h->lineno++;
        }
        buffer_extend(&h->header_buffer,
            h->file_buffer.data + h->file_buffer.position,
            len);
        h->file_buffer.position += len;
        rest -= len;
    }

    /* read sequence line(s) */
    lf = nullptr;
    while (true)
    {
        /* get more data, if necessary */
        rest = fastx_file_fill_buffer(h);

        /* cannot end here */
        if (rest == 0)
        {
           
        }

        /* end when new line starting with + is seen */
        if (lf && (h->file_buffer.data[h->file_buffer.position] == '+'))
        {
            break;
        }

        /* find LF */
        lf = (char*)memchr(h->file_buffer.data + h->file_buffer.position,
            '\n', rest);

        /* copy to sequence buffer */
        uint64_t len = rest;
        if (lf)
        {
            /* LF found, copy up to and including LF */
            len = lf - (h->file_buffer.data + h->file_buffer.position) + 1;
            h->lineno++;
        }

        buffer_filter_extend(h,
            &h->sequence_buffer,
            h->file_buffer.data + h->file_buffer.position,
            len,
            char_fq_action_seq, char_mapping,
            &ok, &illegal_char);
        h->file_buffer.position += len;
        rest -= len;

        if (!ok)
        {
            if ((illegal_char >= 32) && (illegal_char < 127))
            {
                snprintf(msg,
                    200,
                    "Illegal sequence character '%c'",
                    illegal_char);
            }
            else
            {
                snprintf(msg,
                    200,
                    "Illegal sequence character (unprintable, no %d)",
                    (unsigned char)illegal_char);
            }
            
        }
    }

    /* read + line */

    /* skip + character */
    h->file_buffer.position++;
    rest--;

    lf = nullptr;
    while (lf == nullptr)
    {
        /* get more data if buffer empty */
        rest = fastx_file_fill_buffer(h);

        /* cannot end here */
        if (rest == 0)
        {
            printf("Unexpected end of file");
        }

        /* find LF */
        lf = (char*)memchr(h->file_buffer.data + h->file_buffer.position,
            '\n',
            rest);
        /* copy to plusline buffer */
        uint64_t len = rest;
        if (lf)
        {
            /* LF found, copy up to and including LF */
            len = lf - (h->file_buffer.data + h->file_buffer.position) + 1;
            h->lineno++;
        }
        buffer_extend(&h->plusline_buffer,
            h->file_buffer.data + h->file_buffer.position,
            len);
        h->file_buffer.position += len;
        rest -= len;
    }

    /* check that the plus line is empty or identical to @ line */

    bool plusline_invalid = false;
    if (h->header_buffer.length == h->plusline_buffer.length)
    {
        if (memcmp(h->header_buffer.data,
            h->plusline_buffer.data,
            h->header_buffer.length))
        {
            plusline_invalid = true;
        }
    }
    else
    {
        if ((h->plusline_buffer.length > 2) ||
            ((h->plusline_buffer.length == 2) && (h->plusline_buffer.data[0] != '\r')))
        {
            plusline_invalid = true;
        }
    }
    if (plusline_invalid)
    {
        printf("'+' line must be empty or identical to header");
    }

    /* read quality line(s) */

    lf = nullptr;
    while (true)
    {
        /* get more data, if necessary */
        rest = fastx_file_fill_buffer(h);

        /* end if no more data */
        if (rest == 0)
        {
            break;
        }

        /* end if next entry starts : LF + '@' + correct length */
        if (lf &&
            (h->file_buffer.data[h->file_buffer.position] == '@') &&
            (h->quality_buffer.length == h->sequence_buffer.length))
        {
            break;
        }

        /* find LF */
        lf = (char*)memchr(h->file_buffer.data + h->file_buffer.position,
            '\n', rest);

        /* copy to quality buffer */
        uint64_t len = rest;
        if (lf)
        {
            /* LF found, copy up to and including LF */
            len = lf - (h->file_buffer.data + h->file_buffer.position) + 1;
            h->lineno++;
        }

        buffer_filter_extend(h,
            &h->quality_buffer,
            h->file_buffer.data + h->file_buffer.position,
            len,
            char_fq_action_qual, chrmap_identity,
            &ok, &illegal_char);
        h->file_buffer.position += len;
        rest -= len;

        /* break if quality line already too long */
        if (h->quality_buffer.length > h->sequence_buffer.length)
        {
            break;
        }

        if (!ok)
        {
            if ((illegal_char >= 32) && (illegal_char < 127))
            {
                snprintf(msg,
                    200,
                    "Illegal quality character '%c'",
                    illegal_char);
            }
            else
            {
                snprintf(msg,
                    200,
                    "Illegal quality character (unprintable, no %d)",
                    (unsigned char)illegal_char);
            }
            
        }
    }

    if (h->sequence_buffer.length != h->quality_buffer.length)
    {
        printf("Sequence and quality lines must be equally long");
    }

    fastx_filter_header(h, truncateatspace);

    h->seqno++;

    return true;
}

static const char* progress_prompt;
static uint64_t progress_next;
static uint64_t progress_size;
static uint64_t progress_chunk;
static const uint64_t progress_granularity = 200;
static bool progress_show;


void progress_init(const char* prompt, uint64_t size)
{
   
    progress_prompt = prompt;
    progress_size = size;
    progress_chunk = size < progress_granularity ?
        1 : size / progress_granularity;
    progress_next = 0;

   
}


struct kh_bucket_s
{
    unsigned int kmer;
    unsigned int pos; /* 1-based position, 0 = empty */
};

struct kh_handle_s
{
    struct kh_bucket_s* hash;
    unsigned int hash_mask;
    int size;
    int alloc;
    int maxpos;
};

inline void kh_insert_kmer(struct kh_handle_s* kh,
    int k,
    unsigned int kmer,
    unsigned int pos)
{
    /* find free bucket in hash */
    unsigned int j = HASH((char*)&kmer, (k + 3) / 4) & kh->hash_mask;
    while (kh->hash[j].pos)
    {
        j = (j + 1) & kh->hash_mask;
    }

    kh->hash[j].kmer = kmer;
    kh->hash[j].pos = pos;
}




void kh_exit(struct kh_handle_s* kh)
{
    if (kh->hash)
    {
        free(kh->hash);
    }
    free(kh);
}


int kh_find_best_diagonal(struct kh_handle_s* kh, int k, char* seq, int len)
{
    int* diag_counts = (int*)malloc(kh->maxpos * sizeof(int));


    memset(diag_counts, 0, (kh->maxpos * sizeof(int)));

    int kmers = 1 << (2 * k);
    unsigned int kmer_mask = kmers - 1;

    unsigned int bad = kmer_mask;
    unsigned int kmer = 0;
    char* s = seq + len - 1;

    unsigned int* maskmap = chrmap_mask_ambig;

    for (int pos = 0; pos < len; pos++)
    {
        int c = *s--;

        bad <<= 2ULL;
        bad |= maskmap[c];
        bad &= kmer_mask;

        kmer <<= 2ULL;
        kmer |= chrmap_2bit[chrmap_complement[c]];
        kmer &= kmer_mask;

        if (!bad)
        {
            /* find matching buckets in hash */
            unsigned int j = HASH((char*)&kmer, (k + 3) / 4) & kh->hash_mask;
            while (kh->hash[j].pos)
            {
                if (kh->hash[j].kmer == kmer)
                {
                    int fpos = kh->hash[j].pos - 1;
                    int diag = fpos - (pos - k + 1);
                    if (diag >= 0)
                    {
                        diag_counts[diag]++;
                    }
                }
                j = (j + 1) & kh->hash_mask;
            }
        }
    }

    int best_diag_count = -1;
    int best_diag = -1;
    int good_diags = 0;

    for (int d = 0; d < kh->maxpos - k + 1; d++)
    {
        int diag_len = kh->maxpos - d;
        int minmatch = MAX(1, diag_len - k + 1 - k * MAX(diag_len / 20, 0));
        int c = diag_counts[d];

        if (c >= minmatch)
        {
            good_diags++;
        }

        if (c > best_diag_count)
        {
            best_diag_count = c;
            best_diag = d;
        }
    }

    if (good_diags == 1)
    {
        return best_diag;
    }
    else
    {
        return -1;
    }
    free(diag_counts);
}

void kh_find_diagonals(struct kh_handle_s* kh,
    int k,
    char* seq,
    int len,
    int* diags)
{
    memset(diags, 0, (kh->maxpos + len) * sizeof(int));

    int kmers = 1 << (2 * k);
    unsigned int kmer_mask = kmers - 1;

    unsigned int bad = kmer_mask;
    unsigned int kmer = 0;
    char* s = seq + len - 1;

    for (int pos = 0; pos < len; pos++)
    {
        int c = *s--;

        bad <<= 2ULL;
        bad |= chrmap_mask_ambig[c];
        bad &= kmer_mask;

        kmer <<= 2ULL;
        kmer |= chrmap_2bit[chrmap_complement[c]];
        kmer &= kmer_mask;

        if (!bad)
        {
            /* find matching buckets in hash */
            unsigned int j = HASH((char*)&kmer, (k + 3) / 4) & kh->hash_mask;
            while (kh->hash[j].pos)
            {
                if (kh->hash[j].kmer == kmer)
                {
                    int fpos = kh->hash[j].pos - 1;
                    int diag = len + fpos - (pos - k + 1);
                    if (diag >= 0)
                    {
                        diags[diag]++;
                    }
                }
                j = (j + 1) & kh->hash_mask;
            }
        }
    }
    
    
}

void kh_insert_kmers(struct kh_handle_s* kh, int k, char* seq, int len)
{
    int kmers = 1 << (2 * k);
    unsigned int kmer_mask = kmers - 1;

    /* reallocate hash table if necessary */

    if (kh->alloc < 2 * len)
    {
        while (kh->alloc < 2 * len)
        {
            kh->alloc *= 2;
        }
        kh->hash = (struct kh_bucket_s*)
            realloc(kh->hash, kh->alloc * sizeof(struct kh_bucket_s));
    }

    kh->size = 1;
    while (kh->size < 2 * len)
    {
        kh->size *= 2;
    }
    kh->hash_mask = kh->size - 1;

    kh->maxpos = len;

    memset(kh->hash, 0, kh->size * sizeof(struct kh_bucket_s));

    //for (size_t i = 0; i < kh->size * sizeof(struct kh_bucket_s); i++)
    //{
    //    printf("%d", kh->hash[i]);
    //}
    
    unsigned int bad = kmer_mask;
    unsigned int kmer = 0;
    char* s = seq;

    unsigned int* maskmap = chrmap_mask_ambig;

    for (int pos = 0; pos < len; pos++)
    {
        int c = *s++;

        bad <<= 2ULL;
        bad |= maskmap[c];
        bad &= kmer_mask;

        kmer <<= 2ULL;
        kmer |= chrmap_2bit[c];
        kmer &= kmer_mask;

        if (!bad)
        {
            /* 1-based pos of start of kmer */
            kh_insert_kmer(kh, k, kmer, pos - k + 1 + 1);
        }
    }
}






int flagNumber = 0;
void buffer_init(struct fastx_buffer_s* buffer , uint64_t alloc)
{
	buffer->alloc = FASTX_BUFFER_ALLOC;
	buffer->data = (char*)malloc(alloc);
	buffer->data[0] = 0;
	buffer->length = 0;
	buffer->position = 0;
}



FILE* fopen_input(const char* filename)
{
    /* open the input stream given by filename, but use stdin if name is - */
   
        return fopen(filename, "rb");
}

fastx_handle fastx_open(const char* filename)
{
    auto* h = (fastx_handle)malloc(sizeof(struct fastx_s));

    h->fp = 0;



    h->fp = fopen_input(filename);
    if (!h->fp)
    {
       printf("Unable to open file for reading (%s)", filename);
    }

    /* Get mode and size of original (uncompressed) file */

    struct stat  fs;
    int flag = fstat(fileno(h->fp), &fs);
    if (flag)
    {
        printf("Unable to get status for input file (%s)", filename);
    }

    h->is_pipe = 0;

    if (h->is_pipe)
    {
        h->file_size = 0;
    }
    else
    {
        h->file_size = fs.st_size;
    }

        /* autodetect compression (plain, gzipped or bzipped) */

        /* read two characters and compare with magic */

        unsigned char magic[2];

        h->format = 0;

        size_t bytes_read = fread(&magic, 1, 2, h->fp);

        /* close and reopen to avoid problems with gzip library */
        /* rewind was not enough */

        fclose(h->fp);
        h->fp = fopen_input(filename);
        if (!h->fp)
        {
            printf("Unable to open file for reading (%s)", filename);
        }
    


    /* init buffers */

    h->file_position = 0;

    buffer_init(&h->file_buffer, h->file_size);

    /* start filling up file buffer */

    uint64_t rest = fastx_file_fill_buffer(h);

    /* examine first char and see if it starts with > or @ */

    int filetype = 0;
    h->is_empty = true;
    h->is_fastq = false;

    if (rest > 0)
    {
        h->is_empty = false;

        char* first = h->file_buffer.data;

        if (*first == '>')
        {
            filetype = 1;
        }
        else if (*first == '@')
        {
            filetype = 2;
            h->is_fastq = true;
        }

        if (filetype == 0)
        {
            /* close files if unrecognized file type */

           

            fclose(h->fp);
            h->fp = nullptr;

            

            return nullptr;
        }
    }

    /* more initialization */

    buffer_init(&h->header_buffer, h->file_size);
    buffer_init(&h->sequence_buffer, h->file_size);
    buffer_init(&h->plusline_buffer, h->file_size);
    buffer_init(&h->quality_buffer, h->file_size);

    h->stripped_all = 0;

    for (uint64_t& i : h->stripped)
    {
        i = 0;
    }

    h->lineno = 1;
    h->lineno_start = 1;
    h->seqno = -1;

    return h;
}


const int memalignment = 16;


void buffer_makespace(struct fastx_buffer_s* buffer, uint64_t x)
{
    /* make sure there is space for x more chars in buffer */

    if (buffer->length + x > buffer->alloc)
    {
        /* alloc space for x more characters,
           but round up to nearest block size */
        buffer->alloc =
            ((buffer->length + x + 8192 - 1) / 8192)
            * 8192;
        buffer->data = (char*)realloc(buffer->data, buffer->alloc);
    }
}
void buffer_extend(struct fastx_buffer_s* dest_buffer,
    char* source_buf,
    uint64_t len)
{
    buffer_makespace(dest_buffer, len + 1);
    memcpy(dest_buffer->data + dest_buffer->length,
        source_buf,
        len);
    dest_buffer->length += len;
    dest_buffer->data[dest_buffer->length] = 0;
}

uint64_t xftello(FILE* stream)
{
#ifdef _WIN32
	return _ftelli64(stream);
#else
	return ftello(stream);
#endif
}


uint64_t fastx_file_fill_buffer(fastx_handle h)
{
    /* read more data if necessary */
    uint64_t rest = h->file_buffer.length - h->file_buffer.position;

    if (rest > 0)
    {
        return rest;
    }
    else
    {
        uint64_t space = h->file_buffer.alloc - h->file_buffer.length;

        if (space == 0)
        {
            /* back to beginning of buffer */
            h->file_buffer.position = 0;
            h->file_buffer.length = 0;
            space = h->file_buffer.alloc;
        }

        int bytes_read = 0;

            bytes_read = fread(h->file_buffer.data
                + h->file_buffer.position,
                1,
                space,
                h->fp);
     


                h->file_position = xftello(h->fp);


        h->file_buffer.length += bytes_read;
        return bytes_read;
    }
}




char* fastq_get_quality(fastx_handle h)
{
    return h->quality_buffer.data;
}

uint64_t fastq_get_quality_length(fastx_handle h)
{
    return h->quality_buffer.length;
}

uint64_t fastq_get_position(fastx_handle h)
{
    return h->file_position;
}

uint64_t fastq_get_size(fastx_handle h)
{
    return h->file_size;
}

uint64_t fastq_get_lineno(fastx_handle h)
{
    return h->lineno_start;
}

uint64_t fastq_get_seqno(fastx_handle h)
{
    return h->seqno;
}

uint64_t fastq_get_header_length(fastx_handle h)
{
    return h->header_buffer.length;
}

uint64_t fastq_get_sequence_length(fastx_handle h)
{
    return h->sequence_buffer.length;
}

char* fastq_get_header(fastx_handle h)
{
    return h->header_buffer.data;
}

char* fastq_get_sequence(fastx_handle h)
{
    return h->sequence_buffer.data;
}



static fastx_handle fastq_fwd;
static fastx_handle fastq_rev;




FILE* fileopenw(char* filename)
{
    FILE* fp = nullptr;
    fp =  fopen(filename, "w");
    if (!fp)
    {
        printf("Unable to open file for writing (%s)", filename);
    }
    return fp;
}
fastx_handle fastq_open(const char* filename)
{
    fastx_handle h = fastx_open(filename);

    return h;
}

void buffer_free(struct fastx_buffer_s* buffer)
{
    if (buffer->data)
        free(buffer->data);
    buffer->data = 0;
    buffer->alloc = 0;
    buffer->length = 0;
    buffer->position = 0;
}

void fastq_close(fastx_handle h)
{
    /* Warn about stripped chars */

    if (h->stripped_all)
    {
     //   fprintf(stderr, "WARNING: %" PRIu64 " invalid characters stripped from %s file:", h->stripped_all, (h->is_fastq ? "FASTQ" : "FASTA"));
        for (int i = 0; i < 256; i++)
            if (h->stripped[i])
              //  fprintf(stderr, " %c(%" PRIu64 ")", i, h->stripped[i]);
        fprintf(stderr, "\n");

        /*if (opt_log)
        {
            fprintf(fp_log, "WARNING: %" PRIu64 " invalid characters stripped from %s file:", h->stripped_all, (h->is_fastq ? "FASTQ" : "FASTA"));
            for (int i = 0; i < 256; i++)
                if (h->stripped[i])
                    fprintf(fp_log, " %c(%" PRIu64 ")", i, h->stripped[i]);
            fprintf(fp_log, "\n");
        }*/
    }


    fclose(h->fp);
    h->fp = 0;

    buffer_free(&h->file_buffer);
    buffer_free(&h->header_buffer);
    buffer_free(&h->sequence_buffer);
    buffer_free(&h->plusline_buffer);
    buffer_free(&h->quality_buffer);

    h->file_size = 0;
    h->file_position = 0;

    h->lineno = 0;
    h->seqno = -1;

    free(h);
    h = 0;
}




unsigned int chrmap_4bit[256] =
{
    /*
      Map from ascii to 4-bit nucleotide code

        - =      = 0000 =  0
        A = A    = 0001 =  1
        C =  C   = 0010 =  2
        M = AC   = 0011 =  3
        G =   G  = 0100 =  4
        R = A G  = 0101 =  5
        S =  CG  = 0110 =  6
        V = ACG  = 0111 =  7
        T =    T = 1000 =  8
        W = A  T = 1001 =  9
        Y =  C T = 1010 = 10
        H = AC T = 1011 = 11
        K =   GT = 1100 = 12
        D = A GT = 1101 = 13
        B =  CGT = 1110 = 14
        N = ACGT = 1111 = 15

     @   A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
     P   Q   R   S   T   U   V   W   X   Y   Z   [   \   ]   ^   _
    */

     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  1, 14,  2, 13,  0,  0,  4, 11,  0,  0, 12,  0,  3, 15,  0,
     0,  0,  5,  6,  8,  8,  7,  9,  0, 10,  0,  0,  0,  0,  0,  0,
     0,  1, 14,  2, 13,  0,  0,  4, 11,  0,  0, 12,  0,  3, 15,  0,
     0,  0,  5,  6,  8,  8,  7,  9,  0, 10,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};


FILE* fwd;
FILE* rev;

int comparseq(char* seq,char* primer)
{
    int s1_len = strlen(seq);
    int s2_len = strlen(primer);

    for (int i = 0; i <= s1_len - s2_len; i++) {
        int j;
        for (j = 0; j < s2_len; j++) {
            if ((chrmap_4bit[seq[i + j]] & chrmap_4bit[primer[j]])== 0)
                break;
        }
        if (j == s2_len)
           
            return i;
    }

  
    return -1;

}


    int tail = 0;
    bool cutprimer = 0;
    int primer_fwd_len = 0;
    int primer_rev_len = 0;



char* gethitgene(fastx_handle fastq_fwd, fastx_handle fastq_rev,char* primer_fwd, char* primer_rev)
{

    while (fastq_next(fastq_fwd, false, chrmap_upcase)) {
        if (!fastq_next(fastq_rev, false, chrmap_upcase))
        {
            printf("More forward reads than reverse reads");
        }

        int fwd_cont = comparseq(fastq_fwd->sequence_buffer.data, primer_fwd);
        int rev_cont = comparseq(fastq_rev->sequence_buffer.data, primer_rev);

        if (fwd_cont >= 0 && fwd_cont < 10 && rev_cont >= 0 && rev_cont < 10)
        {
            fprintf(fwd, "@%s\n%.*s\n+\n%.*s\n",
             fastq_fwd->header_buffer.data, 
              (int)fastq_fwd->sequence_buffer.length-fwd_cont-tail-primer_fwd_len, 
              fastq_fwd->sequence_buffer.data + fwd_cont+primer_fwd_len,
              (int)fastq_fwd->quality_buffer.length - fwd_cont - tail-primer_fwd_len, 
               fastq_fwd->quality_buffer.data + fwd_cont+primer_fwd_len);

            fprintf(rev, "@%s\n%.*s\n+\n%.*s\n", 
                fastq_rev->header_buffer.data,
                (int)fastq_rev->sequence_buffer.length - rev_cont - tail-primer_rev_len,
                fastq_rev->sequence_buffer.data + rev_cont+primer_rev_len,
                (int)fastq_rev->sequence_buffer.length - rev_cont - tail-primer_rev_len,
                fastq_rev->quality_buffer.data + rev_cont+primer_rev_len      );

        }

    }
 
    return 0;
}

     #include <getopt.h>

    int main(int argc, char *argv[]) {
  

  struct option long_options[] = {
        {"R1", required_argument, nullptr, 'a'},
        {"R2", required_argument, nullptr, 'b'},
        {"P1", required_argument, nullptr, 'c'},
        {"P2", required_argument, nullptr, 'd'},
        {"O1", required_argument, nullptr, 'e'},
        {"O2", required_argument, nullptr, 'f'},
        {"cuttail", required_argument, nullptr, 'k'},
        {"cutprimer", no_argument, nullptr, 'p'},

        {0, 0, 0, 0}
    };

    int c;
    char* primer_fwd = nullptr;
    char* primer_rev = nullptr;


    while ((c = getopt_long(argc, argv, "abcdefkp:", long_options, nullptr)) != -1) {
        switch (c) {
            case 'a':
             fastq_fwd = fastx_open(optarg);
               break;
            case 'b':
             fastq_rev = fastx_open(optarg);
                break;
          case 'c':
              primer_fwd = optarg;
               break;
         case 'd':
              primer_rev = optarg;
             break;
         case 'e':
              fwd = fopen(optarg,"w");
               break;
         case 'f':
               rev = fopen(optarg,"w");
             break;          
         case 'k':
              tail = atoi(optarg);
               break;
         case 'p':
             cutprimer = true;
             break;     

        }

    }


if(cutprimer)
{
    primer_fwd_len = strlen(primer_fwd);
    primer_rev_len = strlen(primer_rev);
   
}

  //  char* primer_fwd = (char*)"TCCGATTACGAYCGYGAGAAGCT";
   // char* primer_rev = (char*)"CSGCYTCGGTSGTCAGGAACAG";
    

  // fastq_fwd = fastx_open("MJ20230508132--MJ230523P_J14--648975028a099c3bdc3c333d--N_1.R1.raw.fastq");
 //  fastq_rev = fastx_open("MJ20230508132--MJ230523P_J14--648975028a099c3bdc3c333d--N_1.R2.raw.fastq");

  //  fwd = fopen("N_1.R1.raw.fastq", "w");
   // rev = fopen("N_1.R2.raw.fastq", "w");


    gethitgene(fastq_fwd, fastq_rev, primer_fwd, primer_rev);


    fastq_close(fastq_fwd);
    fastq_close(fastq_rev);

    fclose(fwd);
    fclose(rev);

    return 0;


      }

  