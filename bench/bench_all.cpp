// Phase 5 deliverable: the comparison table the supervisor asked for.
//
// 100 iterations each (after a 10-iter warmup), pure CPU work, no networking.
// Mean / stddev / median / min / max in milliseconds plus mean RDTSC cycles.
//
// SIX scenarios so the thesis can compare in either direction without the
// methodology being hidden:
//
//   A0  OpenSSL ECDSA_sign (calibration)    libcrypto's ECDSA_do_sign on
//                                           secp256k1. Our standard sign
//                                           should land in the same order
//                                           of magnitude; if it does, the
//                                           rest of our numbers are credible.
//
//   A1  Standard ECDSA s-phase only         k_inv, r*d, z+rd, s; kG and r
//       (matches the original code's        precomputed outside loop. Apples-
//        loop body and the supervisor's     to-apples with C1 (both exclude
//        literal "user computation"         the EC scalar mult).
//        interpretation)
//
//   A2  Standard ECDSA full sign            sign_with_hash(d, h): includes
//       (the user-experienced cost)         RFC 6979 nonce derivation, the
//                                           full kG scalar mult, and s.
//
//   B   Bitcoin multisig 2-of-2             two independent full ECDSA signs
//                                           over the same hash; per-signer
//                                           cost is one A2.
//
//   C1  Threshold ECDSA online phase        threshold_sign(...) with presign
//       (supervisor's "Beaver triplet       precomputed: 2 Beaver triples,
//        + signature" interpretation)       masked inverse, share-based s.
//
//   C2  Threshold ECDSA full pipeline       threshold_presign + threshold_sign:
//       (apples-to-apples with A2)          includes the joint kA*kB*G scalar
//                                           mult that A2 also includes.
//
// CLI:
//   bench_all                          100 iterations, human-readable table
//   bench_all 1000                     1000 iterations (positional, backward-compat)
//   bench_all --iterations 1000        same, named flag
//   bench_all --md                     output the table as Markdown
//   bench_all --csv results.csv        write per-iteration raw data to CSV
//                                      (still prints the summary table to stdout)
//
// The slowdown factors at the bottom let the thesis pick whichever framing
// is most honest for the discussion: literal-vs-literal (C1/A1), supervisor's
// spec (C1/A2), and full-vs-full (C2/A2 and C2/B).

#define OPENSSL_SUPPRESS_DEPRECATED  // libcrypto's legacy EC_KEY/ECDSA_SIG API

#include "bench_util.hpp"
#include "ec_point.hpp"
#include "ecdsa.hpp"
#include "field.hpp"
#include "rng.hpp"
#include "secp256k1.hpp"
#include "sha256.hpp"
#include "tecdsa.hpp"
#include "paillier.hpp"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using tecdsa::bench::BenchResult;
using tecdsa::bench::do_not_optimize;
using tecdsa::bench::print_table_header;
using tecdsa::bench::print_table_header_md;
using tecdsa::bench::print_table_row;
using tecdsa::bench::print_table_row_md;
using tecdsa::bench::run_benchmark;

namespace {

constexpr int kIterations = 100;
constexpr int kWarmup     = 10;

struct CliOptions {
    int         iterations = kIterations;
    bool        markdown   = false;
    std::string csv_path;        // empty => no CSV output
};

CliOptions parse_cli(int argc, char** argv) {
    CliOptions o;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--md") {
            o.markdown = true;
        } else if ((a == "--iterations" || a == "-n") && i + 1 < argc) {
            o.iterations = std::stoi(argv[++i]);
        } else if (a == "--csv" && i + 1 < argc) {
            o.csv_path = argv[++i];
        } else if (a == "--help" || a == "-h") {
            std::cout << "Usage: bench_all [--iterations N | -n N | N]\n"
                      << "                 [--md]            output table as Markdown\n"
                      << "                 [--csv FILE]      write per-iteration data to FILE\n";
            std::exit(0);
        } else {
            // Backward-compat: a single positional int = iteration count.
            try {
                o.iterations = std::stoi(a);
            } catch (...) {
                std::cerr << "Unknown argument: " << a << "\n";
                std::exit(1);
            }
        }
    }
    if (o.iterations < 1) o.iterations = 1;
    return o;
}

// One scenario's identity + measurements, kept around so we can serialize
// everything to CSV after the table is printed.
struct Scenario {
    std::string id;         // e.g. "A0"
    std::string label;      // e.g. "OpenSSL ECDSA_sign (calibration)"
    BenchResult result;
};

void write_csv(const std::string& path,
               const std::vector<Scenario>& scenarios) {
    std::ofstream f(path);
    if (!f) {
        std::cerr << "ERROR: failed to open CSV file: " << path << "\n";
        return;
    }
    f << "scenario_id,scenario_label,iteration,wall_ms,cpu_cycles\n";
    for (const auto& s : scenarios) {
        for (std::size_t i = 0; i < s.result.times_ms.size(); ++i) {
            f << s.id << ',' << '"' << s.label << '"' << ','
              << i << ','
              << s.result.times_ms[i] << ','
              << s.result.cycles[i] << '\n';
        }
    }
    std::cout << "Wrote " << path << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    const CliOptions opts = parse_cli(argc, argv);

    if (!opts.markdown) {
        std::cout << "============================================================\n";
        std::cout << "Threshold ECDSA vs Standard ECDSA - performance comparison\n";
        std::cout << "============================================================\n";
        std::cout << "Iterations  : " << opts.iterations
                  << " (after " << kWarmup << " warmup)\n";
        std::cout << "Curve       : secp256k1\n";
        std::cout << "Compiler    : gcc " << __VERSION__ << "\n";
        std::cout << "Build       : Release (-O3)\n";
        std::cout << "\n";
    } else {
        std::cout << "_Iterations:_ " << opts.iterations
                  << " (after " << kWarmup << " warmup) &nbsp;"
                  << "_Curve:_ secp256k1 &nbsp;"
                  << "_Compiler:_ gcc " << __VERSION__ << " &nbsp;"
                  << "_Build:_ Release `-O3`\n\n";
    }

    tecdsa::Rng rng(0xBE2C5A11ULL);
    const mpz_class& n      = tecdsa::secp256k1::n();
    const mpz_class  half_n = n / 2;

    // ---- Pre-generate inputs (excluded from every timed region) ----------
    const int total = opts.iterations + kWarmup;

    std::vector<tecdsa::KeyPair>          single_keys;
    std::vector<tecdsa::KeyPair>          coSigner_keys;
    std::vector<tecdsa::ThresholdKey>     threshold_keys;
    std::vector<tecdsa::ThresholdPresign> threshold_presigns;
    std::vector<tecdsa::Sha256Hash>       hashes;
    std::vector<mpz_class>                nonces_k;
    std::vector<mpz_class>                nonces_r;
    std::vector<EC_KEY*>                  openssl_keys;

    for (int i = 0; i < total; ++i) {
        single_keys  .push_back(tecdsa::generate_keypair(rng));
        coSigner_keys.push_back(tecdsa::generate_keypair(rng));

        tecdsa::ThresholdKey tk = tecdsa::threshold_keygen(rng);
        threshold_presigns.push_back(tecdsa::threshold_presign(tk, rng));
        threshold_keys    .push_back(tk);

        const std::string msg = "benchmark message #" + std::to_string(i);
        hashes.push_back(tecdsa::double_sha256(msg));

        const mpz_class k = rng.uniform_nonzero_below(n);
        const tecdsa::AffinePoint R = tecdsa::scalar_mul(k, tecdsa::generator());
        nonces_k.push_back(k);
        nonces_r.push_back(R.x % n);

        EC_KEY* ek = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!ek || EC_KEY_generate_key(ek) != 1) {
            std::cerr << "ERROR: OpenSSL EC_KEY generation failed\n";
            return 1;
        }
        openssl_keys.push_back(ek);
    }

    if (opts.markdown) {
        print_table_header_md();
    } else {
        print_table_header();
    }

    auto emit = [&](const std::string& label, const Scenario& s) {
        if (opts.markdown) print_table_row_md(label, s.result.stats);
        else               print_table_row   (label, s.result.stats);
    };

    std::vector<Scenario> scenarios;
    scenarios.reserve(7);

    // ---- A0. OpenSSL ECDSA_sign (calibration baseline) -------------------
    scenarios.push_back({
        "A0", "OpenSSL ECDSA_sign (calibration)",
        run_benchmark(opts.iterations, kWarmup,
            [&](int i) {
                ECDSA_SIG* sig = ECDSA_do_sign(
                    hashes[i].data(),
                    static_cast<int>(hashes[i].size()),
                    openssl_keys[i]);
                do_not_optimize(sig);
                if (sig) ECDSA_SIG_free(sig);
            })
    });
    emit("A0. OpenSSL ECDSA_sign (calibration)", scenarios.back());

    // ---- A1. Standard ECDSA s-phase only (k, r precomputed) --------------
    scenarios.push_back({
        "A1", "Standard ECDSA s-phase only",
        run_benchmark(opts.iterations, kWarmup,
            [&](int i) {
                const mpz_class z   = tecdsa::hash_to_scalar(hashes[i], n);
                const mpz_class kin = tecdsa::mod_inv(nonces_k[i], n);
                const mpz_class rd  = tecdsa::mod_mul(nonces_r[i],
                                                      single_keys[i].d, n);
                const mpz_class zd  = tecdsa::mod_add(z, rd, n);
                mpz_class s         = tecdsa::mod_mul(kin, zd, n);
                if (s > half_n) s = n - s;
                const tecdsa::Signature sig{nonces_r[i], s};
                do_not_optimize(sig);
            })
    });
    emit("A1. Standard ECDSA s-phase only", scenarios.back());

    // ---- A2. Standard ECDSA full sign (kG inside) ------------------------
    scenarios.push_back({
        "A2", "Standard ECDSA full sign",
        run_benchmark(opts.iterations, kWarmup,
            [&](int i) {
                const tecdsa::Signature sig =
                    tecdsa::sign_with_hash(single_keys[i].d, hashes[i]);
                do_not_optimize(sig);
            })
    });
    emit("A2. Standard ECDSA full sign", scenarios.back());

    // ---- B. Bitcoin multisig 2-of-2 (two full standard signs) ------------
    scenarios.push_back({
        "B", "Bitcoin multisig 2-of-2",
        run_benchmark(opts.iterations, kWarmup,
            [&](int i) {
                const tecdsa::Signature sigA =
                    tecdsa::sign_with_hash(single_keys[i].d, hashes[i]);
                const tecdsa::Signature sigB =
                    tecdsa::sign_with_hash(coSigner_keys[i].d, hashes[i]);
                do_not_optimize(sigA);
                do_not_optimize(sigB);
            })
    });
    emit("B.  Bitcoin multisig 2-of-2", scenarios.back());

    // ---- C1. Threshold ECDSA online (presign excluded) -------------------
    scenarios.push_back({
        "C1", "Threshold ECDSA online",
        run_benchmark(opts.iterations, kWarmup,
            [&](int i) {
                const tecdsa::Signature sig = tecdsa::threshold_sign(
                    threshold_keys[i], threshold_presigns[i],
                    hashes[i], rng);
                do_not_optimize(sig);
            })
    });
    emit("C1. Threshold ECDSA online", scenarios.back());

    // ---- C2. Threshold ECDSA full pipeline (presign + sign) --------------
    scenarios.push_back({
        "C2", "Threshold ECDSA full (presign+sign)",
        run_benchmark(opts.iterations, kWarmup,
            [&](int i) {
                const tecdsa::ThresholdPresign p =
                    tecdsa::threshold_presign(threshold_keys[i], rng);
                const tecdsa::Signature sig =
                    tecdsa::threshold_sign(threshold_keys[i], p,
                                           hashes[i], rng);
                do_not_optimize(sig);
            })
    });
    emit("C2. Threshold ECDSA full (presign+sign)", scenarios.back());

    // ---- C3. Threshold MPC + Paillier HE (user-side encrypt) -------------
    // The supervisor confirmed that the "missing" cost making MPC look cheap
    // was the confidentiality layer: Beaver shares are Paillier-encrypted
    // before transmission.  We measure one encrypt() call (single-threaded)
    // added to the MPC online phase.  KeyGen is the Service Provider's job
    // and is excluded.
    //
    // Pre-generate one Paillier key pair outside the timed region (SP cost).
    std::cout << std::flush;  // flush before potentially slow keygen
    const auto paillier_kp = tecdsa::paillier::generate_keys(1024);

    // Pre-generate a Beaver share value per iteration (the "a" share that
    // the user would encrypt before sending to the Service Provider).
    std::vector<mpz_class> beaver_shares;
    beaver_shares.reserve(total);
    for (int i = 0; i < total; ++i) {
        beaver_shares.push_back(rng.uniform_nonzero_below(n));
    }

    scenarios.push_back({
        "C3", "Threshold MPC + Paillier HE (user side)",
        run_benchmark(opts.iterations, kWarmup,
            [&](int i) {
                // MPC online phase (same as C1)
                const tecdsa::Signature sig = tecdsa::threshold_sign(
                    threshold_keys[i], threshold_presigns[i],
                    hashes[i], rng);
                do_not_optimize(sig);
                // + Paillier encrypt of one Beaver share (user-side cost)
                const mpz_class ct = tecdsa::paillier::encrypt(
                    beaver_shares[i], paillier_kp.pub, rng);
                do_not_optimize(ct);
            })
    });
    emit("C3. Threshold MPC + Paillier HE (user)", scenarios.back());

    // ---- Slowdown factors ------------------------------------------------
    auto stats = [&](const std::string& id) -> const tecdsa::bench::Stats& {
        for (const auto& s : scenarios) if (s.id == id) return s.result.stats;
        throw std::runtime_error("unknown scenario id: " + id);
    };

    const double k_c1_a1 = stats("C1").mean_ms / stats("A1").mean_ms;
    const double k_c1_a2 = stats("C1").mean_ms / stats("A2").mean_ms;
    const double k_c2_a2 = stats("C2").mean_ms / stats("A2").mean_ms;
    const double k_c2_b  = stats("C2").mean_ms / stats("B" ).mean_ms;
    const double k_c3_a2 = stats("C3").mean_ms / stats("A2").mean_ms;
    const double k_c3_b  = stats("C3").mean_ms / stats("B" ).mean_ms;
    const double k_a2_a0 = stats("A2").mean_ms / stats("A0").mean_ms;

    if (opts.markdown) {
        std::cout << "\n**Slowdown factor k** (>= 1 means MPC slower; < 1 means MPC faster)\n\n"
                  << "| Comparison | Ratio | Note |\n"
                  << "|---|---:|---|\n";
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "| C1 / A1 | " << k_c1_a1 << "x | literal apples-to-apples (both exclude kG) |\n";
        std::cout << "| C1 / A2 | " << k_c1_a2 << "x | supervisor's Beaver+sign vs full standard |\n";
        std::cout << "| C2 / A2 | " << k_c2_a2 << "x | full apples-to-apples (both include kG) |\n";
        std::cout << "| C2 / B  | " << k_c2_b  << "x | full MPC vs Bitcoin native multisig |\n";
        std::cout << "| **C3 / A2** | **" << k_c3_a2 << "x** | **MPC+Paillier vs standard (the hypothesis)** |\n";
        std::cout << "| C3 / B  | " << k_c3_b  << "x | MPC+Paillier vs Bitcoin multisig |\n";
        std::cout << "| A2 / A0 | " << k_a2_a0 << "x | our standard ECDSA vs OpenSSL (calibration) |\n";
        std::cout.unsetf(std::ios::fixed);
        std::cout << "\n_Hypothesized range (Interim Report 6.1.2): 10x - 50x._\n";
    } else {
        std::cout << "\nSlowdown factor k (>= 1 means MPC slower; < 1 means MPC faster)\n";
        std::cout << std::string(70, '-') << '\n';
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "  C1 / A1   (literal apples-to-apples, both exclude kG)  : "
                  << k_c1_a1 << "x\n";
        std::cout << "  C1 / A2   (supervisor's Beaver+sign vs full standard)  : "
                  << k_c1_a2 << "x\n";
        std::cout << "  C2 / A2   (full apples-to-apples, both include kG)     : "
                  << k_c2_a2 << "x\n";
        std::cout << "  C2 / B    (full MPC vs Bitcoin multisig)               : "
                  << k_c2_b  << "x\n";
        std::cout << "  C3 / A2   (MPC+Paillier vs standard — THE HYPOTHESIS)  : "
                  << k_c3_a2 << "x\n";
        std::cout << "  C3 / B    (MPC+Paillier vs Bitcoin multisig)           : "
                  << k_c3_b  << "x\n";
        std::cout << "  A2 / A0   (our std ECDSA vs OpenSSL: calibration)      : "
                  << k_a2_a0 << "x\n";
        std::cout << "  Hypothesized range (Interim Report 6.1.2)              : 10x - 50x\n";
        std::cout.unsetf(std::ios::fixed);
    }

    // ---- Optional CSV export of raw per-iteration data ------------------
    if (!opts.csv_path.empty()) {
        std::cout << "\n";
        write_csv(opts.csv_path, scenarios);
    }

    for (EC_KEY* k : openssl_keys) EC_KEY_free(k);
    return 0;
}
