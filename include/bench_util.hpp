// Benchmark plumbing: high-resolution wall-clock + CPU-cycle timers, simple
// statistics, and a formatted table printer for the comparison output that
// goes into the supervisor's deliverable table.
//
// Cross-references:
//   - Interim Report sec. 4.1.3: "Average execution time (ms) and CPU cycle
//     counts are logged for analysis" -> mean wall-clock + mean cycles.
//   - Interim Report sec. 6.1.2:   "Slowdown Factor k = Threshold / Standard".
//   - Default iteration count for thesis benchmarks: 100 (override via CLI).

#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include <x86intrin.h>  // __rdtsc on x86 / x86_64

namespace tecdsa::bench {

// Read the CPU's time-stamp counter. Granularity << 1 ns on modern x86.
inline uint64_t rdtsc_now() {
    return static_cast<uint64_t>(__rdtsc());
}

// Force the optimizer to treat `value` as if its address escaped, preventing
// elision of the operation that produced it. Standard Google-Benchmark trick.
template <typename T>
inline void do_not_optimize(const T& value) {
    asm volatile("" : : "g"(&value) : "memory");
}

struct Stats {
    int      n          = 0;
    double   mean_ms    = 0.0;
    double   stddev_ms  = 0.0;
    double   min_ms     = 0.0;
    double   max_ms     = 0.0;
    double   median_ms  = 0.0;
    double   mean_cycles = 0.0;
};

inline Stats summarize(const std::vector<double>& times_ms,
                       const std::vector<uint64_t>& cycles) {
    Stats s;
    s.n = static_cast<int>(times_ms.size());
    if (s.n == 0) return s;

    const double sum = std::accumulate(times_ms.begin(), times_ms.end(), 0.0);
    s.mean_ms = sum / s.n;

    double sq = 0.0;
    for (double t : times_ms) {
        const double d = t - s.mean_ms;
        sq += d * d;
    }
    s.stddev_ms = (s.n > 1) ? std::sqrt(sq / (s.n - 1)) : 0.0;  // sample stddev

    s.min_ms = *std::min_element(times_ms.begin(), times_ms.end());
    s.max_ms = *std::max_element(times_ms.begin(), times_ms.end());

    std::vector<double> sorted = times_ms;
    std::sort(sorted.begin(), sorted.end());
    s.median_ms = sorted[s.n / 2];

    long double cyc_sum = 0;
    for (uint64_t c : cycles) cyc_sum += static_cast<long double>(c);
    s.mean_cycles = static_cast<double>(cyc_sum / s.n);

    return s;
}

// Insert thousands separators into an integer-as-string for the cycle column.
inline std::string with_commas(double value) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(0) << value;
    std::string s = oss.str();
    for (int pos = static_cast<int>(s.size()) - 3; pos > 0; pos -= 3) {
        s.insert(static_cast<std::size_t>(pos), ",");
    }
    return s;
}

inline void print_table_header() {
    std::cout << std::left  << std::setw(40) << "Scenario"
              << std::right
              << std::setw(11) << "mean[ms]"
              << std::setw(11) << "stddev[ms]"
              << std::setw(11) << "median[ms]"
              << std::setw(10) << "min[ms]"
              << std::setw(10) << "max[ms]"
              << std::setw(18) << "mean[cycles]"
              << '\n';
    std::cout << std::string(110, '-') << '\n';
}

inline void print_table_row(const std::string& label, const Stats& s) {
    std::cout << std::left << std::setw(40) << label
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(11) << s.mean_ms
              << std::setw(11) << s.stddev_ms
              << std::setw(11) << s.median_ms
              << std::setw(10) << s.min_ms
              << std::setw(10) << s.max_ms
              << std::setw(18) << with_commas(s.mean_cycles)
              << '\n';
    std::cout.unsetf(std::ios::fixed);
}

// One iteration's measured "cost" -- both elapsed wall time and rdtsc cycles.
struct Measurement {
    double   ms;
    uint64_t cycles;
};

// Time a single invocation of `f`, returning ms + cycles.
template <typename F>
inline Measurement time_once(F&& f) {
    const auto t0 = std::chrono::steady_clock::now();
    const uint64_t c0 = rdtsc_now();
    f();
    const uint64_t c1 = rdtsc_now();
    const auto t1 = std::chrono::steady_clock::now();
    const double ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();
    return Measurement{ms, c1 - c0};
}

// Per-iteration timings PLUS the summary. Per-iteration data is needed for
// CSV export (raw data for the thesis charts); the summary is used for the
// printed table.
struct BenchResult {
    Stats                 stats;
    std::vector<double>   times_ms;
    std::vector<uint64_t> cycles;
};

// Run `f` `warmup` times (untimed), then `n` more times collecting timings.
template <typename F>
inline BenchResult run_benchmark(int n, int warmup, F&& f) {
    for (int i = 0; i < warmup; ++i) f(i);

    BenchResult r;
    r.times_ms.reserve(n);
    r.cycles  .reserve(n);
    for (int i = 0; i < n; ++i) {
        const Measurement m = time_once([&]() { f(warmup + i); });
        r.times_ms.push_back(m.ms);
        r.cycles  .push_back(m.cycles);
    }
    r.stats = summarize(r.times_ms, r.cycles);
    return r;
}

// --- Markdown alternative formatters --------------------------------------
// Same data as the human-readable table, but as a GitHub-flavored Markdown
// table that pastes cleanly into a thesis document or LaTeX `markdown` block.
inline void print_table_header_md() {
    std::cout
        << "| Scenario | mean[ms] | stddev[ms] | median[ms] | min[ms] | max[ms] | mean[cycles] |\n"
        << "|---|---:|---:|---:|---:|---:|---:|\n";
}

inline void print_table_row_md(const std::string& label, const Stats& s) {
    std::cout << "| " << label
              << " | " << std::fixed << std::setprecision(3) << s.mean_ms
              << " | " << s.stddev_ms
              << " | " << s.median_ms
              << " | " << s.min_ms
              << " | " << s.max_ms
              << " | " << with_commas(s.mean_cycles)
              << " |\n";
    std::cout.unsetf(std::ios::fixed);
}

}  // namespace tecdsa::bench
