// Tiny zero-dependency test framework used by every test_*.cpp under tests/.
// CHECK   - records a failure but keeps running so we see ALL broken invariants
//           on the same run.
// REQUIRE - aborts immediately when the property is foundational and continuing
//           past it would be misleading.
// REPORT_AND_RETURN - prints "<n_checks> checks, <n_failures> failures" and
//                     returns a process exit code suitable for ctest.

#pragma once

#include <cstdlib>
#include <iostream>

namespace tecdsa::testing {

inline int& failure_count() {
    static int n = 0;
    return n;
}

inline int& check_count() {
    static int n = 0;
    return n;
}

}  // namespace tecdsa::testing

#define CHECK(cond)                                                           \
    do {                                                                      \
        ++::tecdsa::testing::check_count();                                   \
        if (!(cond)) {                                                        \
            ++::tecdsa::testing::failure_count();                             \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__               \
                      << ": " << #cond << '\n';                               \
        }                                                                     \
    } while (0)

#define REQUIRE(cond)                                                         \
    do {                                                                      \
        ++::tecdsa::testing::check_count();                                   \
        if (!(cond)) {                                                        \
            ++::tecdsa::testing::failure_count();                             \
            std::cerr << "FATAL " << __FILE__ << ':' << __LINE__              \
                      << ": " << #cond << '\n';                               \
            std::exit(1);                                                     \
        }                                                                     \
    } while (0)

#define REPORT_AND_RETURN()                                                   \
    do {                                                                      \
        std::cout << ::tecdsa::testing::check_count() << " checks, "          \
                  << ::tecdsa::testing::failure_count() << " failures\n";     \
        return ::tecdsa::testing::failure_count() == 0 ? 0 : 1;               \
    } while (0)
