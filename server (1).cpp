#include "hqc_common.hpp"

namespace {

int fail(const char* why) {
    std::fprintf(stderr, "session aborted: %s\n", why);
    return 1;
}

int run(const std::string& seed, uint16_t port) {
    using namespace hqc;

    Vec h = derive_h(seed);
    PkeyPtr pkey = rsa_generate();
    Bytes pl = pub_der(pkey.get());
    Vec y = random_sparse("yvec");
    Vec x = random_sparse("xvec");
    Vec s = vxor(x, mul(h, y));
    Bytes sb = vec_to_bytes(s);

    Fd listener(make_listener(port));
    if (listener.fd < 0) return fail("cannot listen on port");
    std::fprintf(stderr, "listening on port %u\n", static_cast<unsigned>(port));

    Fd conn(::accept(listener.fd, nullptr, nullptr));
    if (conn.fd < 0) return fail("accept failed");
    set_timeouts(conn.fd);

    if (!send_frame(conn.fd, sb) || !send_frame(conn.fd, pl)) return fail("send public key failed");

    Bytes ug, vg, tag;
    if (!recv_frame(conn.fd, ug, EXTBYTES) || !recv_frame(conn.fd, vg, EXTBYTES) ||
        !recv_frame(conn.fd, tag, TAG_BYTES))
        return fail("receive failed");
    if (ug.size() != EXTBYTES || vg.size() != EXTBYTES || tag.size() != TAG_BYTES)
        return fail("bad frame size");

    std::vector<uint32_t> pos = interleave_positions(h, s);
    Bytes ucore, vcore, k1a, k1b;
    extract(ug, pos.data(), ucore, k1a);
    extract(vg, pos.data() + HALF_BITS, vcore, k1b);

    Bytes k1(k1a);
    k1.insert(k1.end(), k1b.begin(), k1b.end());

    Vec u = bytes_to_vec(ucore.data());
    Vec v = bytes_to_vec(vcore.data());

    Bytes kp;
    if (!rsa_decrypt(pkey.get(), k1, kp) || kp.size() != MSG) {
        if (!kp.empty()) OPENSSL_cleanse(kp.data(), kp.size());
        return fail("RSA decryption failed");
    }

    Vec kv = derive_kvec(kp.data());
    Vec filt = vxor(vxor(v, mul(y, u)), mul(x, kv));

    uint8_t mp[MSG];
    if (!ecc_decode(filt, mp)) {
        OPENSSL_cleanse(kp.data(), kp.size());
        return fail("ECC decoding failed");
    }

    int rc = 0;
    const char* why = nullptr;

    Core re = derive_core(h, s, pl, mp, kp.data());
    Bytes u2 = vec_to_bytes(re.u);
    Bytes v2 = vec_to_bytes(re.v);
    if (!ct_equal(u2, ucore) || !ct_equal(v2, vcore)) {
        why = "re-encryption check failed";
    } else {
        Bytes ug2 = embed(u2, pos.data(), k1.data());
        Bytes vg2 = embed(v2, pos.data() + HALF_BITS, k1.data() + HALF_BITS / 8);
        if (!ct_equal(ug2, ug) || !ct_equal(vg2, vg)) why = "re-packing check failed";
    }

    if (!why) {
        Bytes tag2 = auth_tag(kp.data(), mp, ug, vg);
        if (!ct_equal(tag2, tag)) why = "auth tag check failed";
    }

    if (!why) {
        Bytes conf = confirm_tag(kp.data(), mp, tag);
        if (!send_frame(conn.fd, conf)) {
            why = "send confirmation failed";
        } else {
            std::printf("AES key m' = %s\n", to_hex(mp, MSG).c_str());
            std::fflush(stdout);
        }
    }

    if (why) rc = fail(why);

    OPENSSL_cleanse(kp.data(), kp.size());
    OPENSSL_cleanse(mp, sizeof mp);
    return rc;
}

}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::fprintf(stderr, "usage: %s <seed> [port]\n", argv[0]);
        return 2;
    }
    uint16_t port = 9000;
    if (argc == 3 && !hqc::parse_port(argv[2], port)) {
        std::fprintf(stderr, "invalid port\n");
        return 2;
    }
    std::signal(SIGPIPE, SIG_IGN);
    try {
        return run(argv[1], port);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
