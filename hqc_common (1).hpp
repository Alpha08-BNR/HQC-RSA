#ifndef HQC_COMMON_HPP
#define HQC_COMMON_HPP

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

namespace hqc {

using Bytes = std::vector<uint8_t>;
using Vec = std::vector<uint64_t>;

constexpr size_t N = 17669;
constexpr size_t WT = 66;
constexpr size_t MSG = 32;
constexpr size_t WORDS = (N + 63) / 64;
constexpr size_t NBYTES = (N + 7) / 8;
constexpr size_t HALF_BITS = 1024;
constexpr size_t K1_BYTES = 256;
constexpr size_t EXT = N + HALF_BITS;
constexpr size_t EXTBYTES = (EXT + 7) / 8;
constexpr size_t TAG_BYTES = 32;
constexpr size_t RS_N = 68;
constexpr size_t RS_K = 32;
constexpr size_t RS_P = RS_N - RS_K;
constexpr size_t RM_LEN = 128;
constexpr size_t RM_DUP = 2;
constexpr size_t RM_BLOCK = RM_LEN * RM_DUP;
constexpr uint64_t LAST_MASK = (1ULL << (N % 64)) - 1ULL;

static_assert(N % 64 != 0, "N must not be a multiple of 64");
static_assert(RS_N * RM_BLOCK <= N, "ECC expansion must fit in N bits");

inline uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

inline void keccak_f(uint64_t st[25]) {
    static const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    static const unsigned ROT[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                     27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
    static const int PI[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
    for (int round = 0; round < 24; ++round) {
        uint64_t bc[5];
        for (int i = 0; i < 5; ++i) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; ++i) {
            uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        uint64_t t = st[1];
        for (int i = 0; i < 24; ++i) {
            int j = PI[i];
            uint64_t tmp = st[j];
            st[j] = rotl64(t, ROT[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; ++i) bc[i] = st[j + i];
            for (int i = 0; i < 5; ++i) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= RC[round];
    }
}

class Shake256 {
public:
    static constexpr size_t RATE = 136;

    Shake256() : pos_(0), done_(false) { std::memset(st_, 0, sizeof st_); }

    Shake256& put(const uint8_t* d, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            st_[pos_ >> 3] ^= static_cast<uint64_t>(d[i]) << (8 * (pos_ & 7));
            if (++pos_ == RATE) {
                keccak_f(st_);
                pos_ = 0;
            }
        }
        return *this;
    }
    Shake256& put(const Bytes& b) { return put(b.data(), b.size()); }
    Shake256& put(const std::string& s) {
        return put(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    void squeeze(uint8_t* out, size_t n) {
        if (!done_) finalize();
        for (size_t i = 0; i < n; ++i) {
            if (pos_ == RATE) {
                keccak_f(st_);
                pos_ = 0;
            }
            out[i] = static_cast<uint8_t>((st_[pos_ >> 3] >> (8 * (pos_ & 7))) & 0xFF);
            ++pos_;
        }
    }

    Bytes out(size_t n) {
        Bytes r(n);
        squeeze(r.data(), n);
        return r;
    }

private:
    void finalize() {
        st_[pos_ >> 3] ^= static_cast<uint64_t>(0x1F) << (8 * (pos_ & 7));
        st_[(RATE - 1) >> 3] ^= static_cast<uint64_t>(0x80) << (8 * ((RATE - 1) & 7));
        keccak_f(st_);
        pos_ = 0;
        done_ = true;
    }

    uint64_t st_[25];
    size_t pos_;
    bool done_;
};

inline uint32_t next32(Shake256& s) {
    uint8_t b[4];
    s.squeeze(b, 4);
    return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
}

inline uint32_t rand_below(Shake256& s, uint32_t bound) {
    uint32_t th = (0u - bound) % bound;
    uint32_t r;
    do {
        r = next32(s);
    } while (r < th);
    return r % bound;
}

inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc |= static_cast<uint8_t>(a[i] ^ b[i]);
    return acc == 0;
}

inline bool ct_equal(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    return ct_equal(a.data(), b.data(), a.size());
}

inline Vec vec_zero() { return Vec(WORDS, 0); }

inline Vec vxor(const Vec& a, const Vec& b) {
    Vec r(WORDS);
    for (size_t i = 0; i < WORDS; ++i) r[i] = a[i] ^ b[i];
    return r;
}

inline bool getbit(const Vec& v, size_t i) { return (v[i >> 6] >> (i & 63)) & 1ULL; }

inline void setbit(Vec& v, size_t i) { v[i >> 6] |= 1ULL << (i & 63); }

inline size_t popcount(const Vec& v) {
    size_t c = 0;
    for (uint64_t w : v) c += static_cast<size_t>(__builtin_popcountll(w));
    return c;
}

inline Bytes vec_to_bytes(const Vec& v) {
    Bytes b(NBYTES);
    for (size_t i = 0; i < NBYTES; ++i) b[i] = static_cast<uint8_t>((v[i >> 3] >> (8 * (i & 7))) & 0xFF);
    return b;
}

inline Vec bytes_to_vec(const uint8_t* b) {
    Vec v(WORDS, 0);
    for (size_t i = 0; i < NBYTES; ++i) v[i >> 3] |= static_cast<uint64_t>(b[i]) << (8 * (i & 7));
    v[WORDS - 1] &= LAST_MASK;
    return v;
}

inline bool parse_vec(const Bytes& b, Vec& out) {
    if (b.size() != NBYTES) return false;
    if ((b[NBYTES - 1] >> (N % 8)) != 0) return false;
    out = bytes_to_vec(b.data());
    return true;
}

inline Vec mul(const Vec& a, const Vec& b) {
    const Vec* sp = &a;
    const Vec* dn = &b;
    if (popcount(a) > popcount(b)) std::swap(sp, dn);
    const uint64_t* d = dn->data();
    std::vector<uint64_t> acc(2 * WORDS + 1, 0);
    for (size_t w = 0; w < WORDS; ++w) {
        uint64_t bits = (*sp)[w];
        while (bits) {
            unsigned t = static_cast<unsigned>(__builtin_ctzll(bits));
            bits &= bits - 1;
            uint64_t* dst = acc.data() + w;
            if (t == 0) {
                for (size_t j = 0; j < WORDS; ++j) dst[j] ^= d[j];
            } else {
                const unsigned rt = 64 - t;
                for (size_t j = 0; j < WORDS; ++j) {
                    dst[j] ^= d[j] << t;
                    dst[j + 1] ^= d[j] >> rt;
                }
            }
        }
    }
    constexpr size_t SW = N >> 6;
    constexpr unsigned SB = N & 63;
    Vec r(WORDS);
    for (size_t j = 0; j < WORDS; ++j) {
        uint64_t hi = (acc[SW + j] >> SB) | (acc[SW + j + 1] << (64 - SB));
        r[j] = acc[j] ^ hi;
    }
    r[WORDS - 1] &= LAST_MASK;
    return r;
}

inline Vec sample_sparse(Shake256& s, size_t wt) {
    Vec v(WORDS, 0);
    size_t cnt = 0;
    while (cnt < wt) {
        uint32_t p = rand_below(s, static_cast<uint32_t>(N));
        uint64_t bit = 1ULL << (p & 63);
        uint64_t& w = v[p >> 6];
        if (w & bit) continue;
        w |= bit;
        ++cnt;
    }
    return v;
}

inline Vec random_sparse(const std::string& label) {
    Bytes seed(32);
    if (RAND_bytes(seed.data(), static_cast<int>(seed.size())) != 1)
        throw std::runtime_error("RAND_bytes failed");
    Shake256 sh;
    sh.put(label).put(seed);
    Vec v = sample_sparse(sh, WT);
    OPENSSL_cleanse(seed.data(), seed.size());
    return v;
}

inline Vec derive_h(const std::string& seed) {
    Shake256 sh;
    sh.put(std::string("hvec")).put(seed);
    Bytes b = sh.out(NBYTES);
    return bytes_to_vec(b.data());
}

inline Vec derive_kvec(const uint8_t* k) {
    Shake256 sh;
    sh.put(std::string("Kvec")).put(k, MSG);
    Bytes b = sh.out(NBYTES);
    return bytes_to_vec(b.data());
}

struct GF {
    uint8_t ex[512];
    uint8_t lg[256];
    GF() {
        std::memset(ex, 0, sizeof ex);
        std::memset(lg, 0, sizeof lg);
        unsigned x = 1;
        for (unsigned i = 0; i < 255; ++i) {
            ex[i] = static_cast<uint8_t>(x);
            lg[x] = static_cast<uint8_t>(i);
            x <<= 1;
            if (x & 0x100) x ^= 0x11D;
        }
        for (unsigned i = 255; i < 512; ++i) ex[i] = ex[i - 255];
    }
};

inline const GF& gf() {
    static const GF g;
    return g;
}

inline uint8_t gmul(uint8_t a, uint8_t b) {
    if (!a || !b) return 0;
    const GF& g = gf();
    return g.ex[g.lg[a] + g.lg[b]];
}

inline uint8_t gdiv(uint8_t a, uint8_t b) {
    if (!a) return 0;
    const GF& g = gf();
    return g.ex[g.lg[a] + 255 - g.lg[b]];
}

inline uint8_t galpha(int e) { return gf().ex[((e % 255) + 255) % 255]; }

inline uint8_t gpow(uint8_t a, int e) {
    if (e == 0) return 1;
    if (!a) return 0;
    const GF& g = gf();
    return g.ex[(static_cast<int>(g.lg[a]) * e) % 255];
}

struct RsGen {
    uint8_t g[RS_P + 1];
    RsGen() {
        std::memset(g, 0, sizeof g);
        g[0] = 1;
        int deg = 0;
        for (size_t i = 0; i < RS_P; ++i) {
            uint8_t a = galpha(static_cast<int>(i));
            for (int j = deg + 1; j >= 0; --j) {
                uint8_t prev = j > 0 ? g[j - 1] : 0;
                g[j] = prev ^ gmul(a, g[j]);
            }
            ++deg;
        }
    }
};

inline const RsGen& rs_gen() {
    static const RsGen g;
    return g;
}

inline void rs_encode(const uint8_t* msg, uint8_t* cw) {
    const RsGen& G = rs_gen();
    uint8_t r[RS_P];
    std::memset(r, 0, sizeof r);
    for (int i = static_cast<int>(RS_K) - 1; i >= 0; --i) {
        uint8_t fb = msg[i] ^ r[RS_P - 1];
        for (size_t j = RS_P - 1; j > 0; --j) r[j] = r[j - 1] ^ gmul(fb, G.g[j]);
        r[0] = gmul(fb, G.g[0]);
    }
    std::memcpy(cw, r, RS_P);
    std::memcpy(cw + RS_P, msg, RS_K);
}

inline bool rs_syndromes(const uint8_t* cw, uint8_t* S) {
    bool any = false;
    for (size_t j = 0; j < RS_P; ++j) {
        uint8_t a = galpha(static_cast<int>(j));
        uint8_t acc = 0;
        for (int i = static_cast<int>(RS_N) - 1; i >= 0; --i) acc = gmul(acc, a) ^ cw[i];
        S[j] = acc;
        if (acc) any = true;
    }
    return any;
}

inline bool rs_decode(const uint8_t* in, uint8_t* msg) {
    uint8_t cw[RS_N];
    std::memcpy(cw, in, RS_N);
    uint8_t S[RS_P];
    if (rs_syndromes(cw, S)) {
        uint8_t C[RS_P + 1], B[RS_P + 1], T[RS_P + 1];
        std::memset(C, 0, sizeof C);
        std::memset(B, 0, sizeof B);
        C[0] = 1;
        B[0] = 1;
        int L = 0;
        int m = 1;
        uint8_t b = 1;
        for (int n = 0; n < static_cast<int>(RS_P); ++n) {
            uint8_t d = S[n];
            for (int i = 1; i <= L; ++i) d ^= gmul(C[i], S[n - i]);
            if (!d) {
                ++m;
                continue;
            }
            std::memcpy(T, C, sizeof C);
            uint8_t coef = gdiv(d, b);
            for (int i = 0; i + m <= static_cast<int>(RS_P); ++i) C[i + m] ^= gmul(coef, B[i]);
            if (2 * L <= n) {
                L = n + 1 - L;
                std::memcpy(B, T, sizeof B);
                b = d;
                m = 1;
            } else {
                ++m;
            }
        }
        if (L > static_cast<int>(RS_P / 2)) return false;
        int locs[RS_P];
        int nl = 0;
        for (int p = 0; p < static_cast<int>(RS_N); ++p) {
            uint8_t xi = galpha(255 - p);
            uint8_t acc = 0;
            for (int i = L; i >= 0; --i) acc = gmul(acc, xi) ^ C[i];
            if (!acc) {
                if (nl >= static_cast<int>(RS_P)) return false;
                locs[nl++] = p;
            }
        }
        if (nl != L) return false;
        uint8_t O[RS_P];
        for (size_t k = 0; k < RS_P; ++k) {
            uint8_t acc = 0;
            for (size_t i = 0; i <= k && i <= static_cast<size_t>(L); ++i) acc ^= gmul(C[i], S[k - i]);
            O[k] = acc;
        }
        for (int q = 0; q < nl; ++q) {
            int p = locs[q];
            uint8_t xi = galpha(255 - p);
            uint8_t om = 0;
            for (int k = static_cast<int>(RS_P) - 1; k >= 0; --k) om = gmul(om, xi) ^ O[k];
            uint8_t der = 0;
            for (int i = 1; i <= L; i += 2) der ^= gmul(C[i], gpow(xi, i - 1));
            if (!der) return false;
            cw[p] ^= gmul(galpha(p), gdiv(om, der));
        }
        if (rs_syndromes(cw, S)) return false;
    }
    std::memcpy(msg, cw + RS_P, RS_K);
    return true;
}

inline void rm_encode_byte(uint8_t b, Vec& v, size_t block) {
    unsigned a0 = b & 1u;
    unsigned a = static_cast<unsigned>(b) >> 1;
    for (unsigned x = 0; x < RM_LEN; ++x) {
        unsigned bit = a0 ^ static_cast<unsigned>(__builtin_parity(a & x));
        if (bit) {
            for (size_t d = 0; d < RM_DUP; ++d) setbit(v, block * RM_BLOCK + d * RM_LEN + x);
        }
    }
}

inline uint8_t rm_decode_block(const Vec& v, size_t block) {
    int T[RM_LEN];
    for (size_t x = 0; x < RM_LEN; ++x) {
        int sum = 0;
        for (size_t d = 0; d < RM_DUP; ++d)
            sum += 1 - 2 * static_cast<int>(getbit(v, block * RM_BLOCK + d * RM_LEN + x));
        T[x] = sum;
    }
    for (size_t len = 1; len < RM_LEN; len <<= 1) {
        for (size_t i = 0; i < RM_LEN; i += 2 * len) {
            for (size_t j = i; j < i + len; ++j) {
                int u = T[j];
                int w = T[j + len];
                T[j] = u + w;
                T[j + len] = u - w;
            }
        }
    }
    size_t best = 0;
    int bestabs = std::abs(T[0]);
    for (size_t i = 1; i < RM_LEN; ++i) {
        int av = std::abs(T[i]);
        if (av > bestabs) {
            bestabs = av;
            best = i;
        }
    }
    unsigned a0 = T[best] < 0 ? 1u : 0u;
    return static_cast<uint8_t>((best << 1) | a0);
}

inline Vec ecc_encode(const uint8_t* m) {
    uint8_t cw[RS_N];
    rs_encode(m, cw);
    Vec v = vec_zero();
    for (size_t i = 0; i < RS_N; ++i) rm_encode_byte(cw[i], v, i);
    return v;
}

inline bool ecc_decode(const Vec& v, uint8_t* m) {
    uint8_t cw[RS_N];
    for (size_t i = 0; i < RS_N; ++i) cw[i] = rm_decode_block(v, i);
    return rs_decode(cw, m);
}

struct Core {
    Vec u;
    Vec v;
};

inline Core derive_core(const Vec& h, const Vec& s, const Bytes& pl, const uint8_t* m,
                        const uint8_t* k) {
    Shake256 sh;
    sh.put(std::string("noise")).put(m, MSG).put(k, MSG).put(vec_to_bytes(s)).put(pl);
    Vec r1 = sample_sparse(sh, WT);
    Vec r2 = sample_sparse(sh, WT);
    Vec e = sample_sparse(sh, WT);
    Vec c = ecc_encode(m);
    Vec kv = derive_kvec(k);
    Vec t = vxor(r2, kv);
    Core out;
    out.u = vxor(r1, mul(h, t));
    out.v = vxor(vxor(c, e), mul(s, t));
    return out;
}

inline std::vector<uint32_t> interleave_positions(const Vec& h, const Vec& s) {
    Shake256 sh;
    sh.put(std::string("interleave_k1")).put(vec_to_bytes(h)).put(vec_to_bytes(s));
    std::vector<uint32_t> idx(EXT);
    std::iota(idx.begin(), idx.end(), 0u);
    for (size_t i = 0; i < 2 * HALF_BITS; ++i) {
        size_t j = i + rand_below(sh, static_cast<uint32_t>(EXT - i));
        std::swap(idx[i], idx[j]);
    }
    idx.resize(2 * HALF_BITS);
    return idx;
}

inline Bytes embed(const Bytes& core, const uint32_t* pos, const uint8_t* half) {
    std::vector<int32_t> slot(EXT, -1);
    for (size_t i = 0; i < HALF_BITS; ++i) slot[pos[i]] = static_cast<int32_t>(i);
    Bytes out(EXTBYTES, 0);
    size_t ci = 0;
    for (size_t o = 0; o < EXT; ++o) {
        unsigned bit;
        if (slot[o] >= 0) {
            size_t i = static_cast<size_t>(slot[o]);
            bit = (static_cast<unsigned>(half[i >> 3]) >> (i & 7)) & 1u;
        } else {
            bit = (static_cast<unsigned>(core[ci >> 3]) >> (ci & 7)) & 1u;
            ++ci;
        }
        out[o >> 3] = static_cast<uint8_t>(out[o >> 3] | (bit << (o & 7)));
    }
    return out;
}

inline void extract(const Bytes& gop, const uint32_t* pos, Bytes& core, Bytes& half) {
    std::vector<int32_t> slot(EXT, -1);
    for (size_t i = 0; i < HALF_BITS; ++i) slot[pos[i]] = static_cast<int32_t>(i);
    core.assign(NBYTES, 0);
    half.assign(HALF_BITS / 8, 0);
    size_t ci = 0;
    for (size_t o = 0; o < EXT; ++o) {
        unsigned bit = (static_cast<unsigned>(gop[o >> 3]) >> (o & 7)) & 1u;
        if (slot[o] >= 0) {
            size_t i = static_cast<size_t>(slot[o]);
            half[i >> 3] = static_cast<uint8_t>(half[i >> 3] | (bit << (i & 7)));
        } else {
            core[ci >> 3] = static_cast<uint8_t>(core[ci >> 3] | (bit << (ci & 7)));
            ++ci;
        }
    }
}

inline Bytes auth_tag(const uint8_t* k, const uint8_t* m, const Bytes& ug, const Bytes& vg) {
    Shake256 sh;
    sh.put(std::string("auth_tag")).put(k, MSG).put(m, MSG).put(ug).put(vg);
    return sh.out(TAG_BYTES);
}

inline Bytes confirm_tag(const uint8_t* k, const uint8_t* m, const Bytes& tag) {
    Shake256 sh;
    sh.put(std::string("confirm")).put(k, MSG).put(m, MSG).put(tag);
    return sh.out(TAG_BYTES);
}

inline std::string to_hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}

struct PkeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct CtxDeleter {
    void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using CtxPtr = std::unique_ptr<EVP_PKEY_CTX, CtxDeleter>;

inline PkeyPtr rsa_generate() {
    PkeyPtr k(EVP_RSA_gen(2048));
    if (!k) throw std::runtime_error("EVP_RSA_gen failed");
    return k;
}

inline Bytes pub_der(EVP_PKEY* pk) {
    int len = i2d_PUBKEY(pk, nullptr);
    if (len <= 0) throw std::runtime_error("i2d_PUBKEY failed");
    Bytes out(static_cast<size_t>(len));
    unsigned char* p = out.data();
    if (i2d_PUBKEY(pk, &p) != len) throw std::runtime_error("i2d_PUBKEY failed");
    return out;
}

inline PkeyPtr load_pub(const Bytes& der) {
    const unsigned char* p = der.data();
    PkeyPtr k(d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size())));
    if (!k) return PkeyPtr();
    if (EVP_PKEY_id(k.get()) != EVP_PKEY_RSA || EVP_PKEY_bits(k.get()) != 2048) return PkeyPtr();
    return k;
}

inline bool rsa_encrypt(EVP_PKEY* pk, const uint8_t* in, size_t inlen, Bytes& out) {
    CtxPtr ctx(EVP_PKEY_CTX_new(pk, nullptr));
    if (!ctx) return false;
    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) return false;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) return false;
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, in, inlen) <= 0) return false;
    out.assign(outlen, 0);
    if (EVP_PKEY_encrypt(ctx.get(), out.data(), &outlen, in, inlen) <= 0) return false;
    out.resize(outlen);
    return true;
}

inline bool rsa_decrypt(EVP_PKEY* pk, const Bytes& in, Bytes& out) {
    CtxPtr ctx(EVP_PKEY_CTX_new(pk, nullptr));
    if (!ctx) return false;
    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) return false;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) return false;
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, in.data(), in.size()) <= 0) return false;
    out.assign(outlen, 0);
    if (EVP_PKEY_decrypt(ctx.get(), out.data(), &outlen, in.data(), in.size()) <= 0) {
        OPENSSL_cleanse(out.data(), out.size());
        return false;
    }
    out.resize(outlen);
    return true;
}

struct Fd {
    int fd;
    explicit Fd(int f = -1) : fd(f) {}
    ~Fd() {
        if (fd >= 0) ::close(fd);
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

inline void set_timeouts(int fd) {
    timeval tv;
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

inline bool send_all(int fd, const uint8_t* p, size_t n) {
    while (n > 0) {
        ssize_t r = ::send(fd, p, n, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        p += r;
        n -= static_cast<size_t>(r);
    }
    return true;
}

inline bool recv_all(int fd, uint8_t* p, size_t n) {
    while (n > 0) {
        ssize_t r = ::recv(fd, p, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        p += r;
        n -= static_cast<size_t>(r);
    }
    return true;
}

inline bool send_frame(int fd, const Bytes& b) {
    uint8_t hdr[4];
    uint32_t n = static_cast<uint32_t>(b.size());
    hdr[0] = static_cast<uint8_t>(n >> 24);
    hdr[1] = static_cast<uint8_t>(n >> 16);
    hdr[2] = static_cast<uint8_t>(n >> 8);
    hdr[3] = static_cast<uint8_t>(n);
    return send_all(fd, hdr, 4) && send_all(fd, b.data(), b.size());
}

inline bool recv_frame(int fd, Bytes& out, size_t maxlen) {
    uint8_t hdr[4];
    if (!recv_all(fd, hdr, 4)) return false;
    size_t n = (static_cast<size_t>(hdr[0]) << 24) | (static_cast<size_t>(hdr[1]) << 16) |
               (static_cast<size_t>(hdr[2]) << 8) | static_cast<size_t>(hdr[3]);
    if (n > maxlen) return false;
    out.assign(n, 0);
    return recv_all(fd, out.data(), n);
}

inline int make_listener(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 || ::listen(fd, 1) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

inline int connect_to(const char* host, const char* port) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

inline bool parse_port(const char* s, uint16_t& out) {
    char* end = nullptr;
    errno = 0;
    long v = std::strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > 65535) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

}

#endif
