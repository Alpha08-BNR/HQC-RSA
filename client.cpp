#include "hqc_common.hpp"

namespace {

int fail(const char* why) {
    std::fprintf(stderr, "session aborted: %s\n", why);
    return 1;
}

int run(const std::string& seed, const char* host, const char* port) {
    using namespace hqc;

    Fd conn(connect_to(host, port));
    if (conn.fd < 0) return fail("cannot connect");
    set_timeouts(conn.fd);

    Bytes sb, pl;
    if (!recv_frame(conn.fd, sb, NBYTES) || !recv_frame(conn.fd, pl, 4096))
        return fail("receive public key failed");

    Vec s;
    if (!parse_vec(sb, s)) return fail("malformed s");
    PkeyPtr pk = load_pub(pl);
    if (!pk) return fail("invalid RSA public key");

    Vec h = derive_h(seed);

    uint8_t m[MSG], k[MSG];
    if (RAND_bytes(m, static_cast<int>(MSG)) != 1 || RAND_bytes(k, static_cast<int>(MSG)) != 1)
        return fail("RAND_bytes failed");

    int rc = 0;
    const char* why = nullptr;

    do {
        Core core = derive_core(h, s, pl, m, k);

        Bytes k1;
        if (!rsa_encrypt(pk.get(), k, MSG, k1) || k1.size() != K1_BYTES) {
            why = "RSA encryption failed";
            break;
        }

        std::vector<uint32_t> pos = interleave_positions(h, s);
        Bytes ug = embed(vec_to_bytes(core.u), pos.data(), k1.data());
        Bytes vg = embed(vec_to_bytes(core.v), pos.data() + HALF_BITS, k1.data() + HALF_BITS / 8);
        Bytes tag = auth_tag(k, m, ug, vg);

        if (!send_frame(conn.fd, ug) || !send_frame(conn.fd, vg) || !send_frame(conn.fd, tag)) {
            why = "send failed";
            break;
        }

        Bytes conf;
        if (!recv_frame(conn.fd, conf, TAG_BYTES)) {
            why = "no confirmation received";
            break;
        }
        Bytes expect = confirm_tag(k, m, tag);
        if (!ct_equal(conf, expect)) {
            why = "confirmation mismatch";
            break;
        }

        std::printf("AES key m = %s\n", to_hex(m, MSG).c_str());
        std::fflush(stdout);
    } while (false);

    if (why) rc = fail(why);

    OPENSSL_cleanse(m, sizeof m);
    OPENSSL_cleanse(k, sizeof k);
    return rc;
}

}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 4) {
        std::fprintf(stderr, "usage: %s <seed> [host] [port]\n", argv[0]);
        return 2;
    }
    const char* host = argc >= 3 ? argv[2] : "127.0.0.1";
    const char* port = argc == 4 ? argv[3] : "9000";
    uint16_t pn = 0;
    if (!hqc::parse_port(port, pn)) {
        std::fprintf(stderr, "invalid port\n");
        return 2;
    }
    std::signal(SIGPIPE, SIG_IGN);
    try {
        return run(argv[1], host, port);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
