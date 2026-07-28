cmake_minimum_required(VERSION 3.16)
project(tecdsa_thesis LANGUAGES CXX)

# C++17 across the project. Plenty for what we need; nothing requires 20.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Release so the benchmark numbers we publish are honest.
# Override with: cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Default build type" FORCE)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
    add_compile_options($<$<CONFIG:Release>:-O3>)
    add_compile_options($<$<CONFIG:Release>:-DNDEBUG>)
endif()

# --- GMP discovery -----------------------------------------------------------
# On MSYS2 UCRT64 these come from the package mingw-w64-ucrt-x86_64-gmp.
# We use find_library/find_path directly so this also works on plain Linux
# installs (libgmp-dev) without needing pkg-config to expose gmpxx.
find_library(GMP_LIBRARY    NAMES gmp   REQUIRED)
find_library(GMPXX_LIBRARY  NAMES gmpxx REQUIRED)
find_path(GMP_INCLUDE_DIR   NAMES gmpxx.h gmp.h REQUIRED)

message(STATUS "GMP    library : ${GMP_LIBRARY}")
message(STATUS "GMPXX  library : ${GMPXX_LIBRARY}")
message(STATUS "GMP    include : ${GMP_INCLUDE_DIR}")

# OpenSSL is required for: (a) test_openssl_interop and test_tecdsa to verify
# our signatures with libcrypto, (b) bench_all's A0 calibration baseline.
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL        : ${OPENSSL_VERSION}")

# --- Core library ------------------------------------------------------------
# Everything ECDSA, threshold-ECDSA, benchmarks and tests will share lives
# here. Headers are exposed via include/ so consumers don't need to know the
# internal source layout.
add_library(tecdsa_core STATIC
    src/rng.cpp
    src/secp256k1.cpp
    src/sha256.cpp
    src/ec_point.cpp
    src/rfc6979.cpp
    src/ecdsa.cpp
    src/beaver.cpp
    src/tecdsa.cpp
    src/paillier.cpp
)
target_include_directories(tecdsa_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${GMP_INCLUDE_DIR}
)
# gmpxx must come before gmp on the link line (it depends on the C library).
target_link_libraries(tecdsa_core PUBLIC ${GMPXX_LIBRARY} ${GMP_LIBRARY})

# --- Phase 0: GMP linkage smoke test ----------------------------------------
add_executable(hello_gmp src/hello_gmp.cpp)
target_link_libraries(hello_gmp PRIVATE tecdsa_core)

# --- Phase 5: comparison benchmark (the supervisor's deliverable) ----------
# Links OpenSSL too: scenario A0 uses ECDSA_do_sign as a calibration baseline
# so the thesis can argue "our standard ECDSA timing is within X of a
# production library, therefore the rest of our numbers are credible".
add_executable(bench_all bench/bench_all.cpp)
target_link_libraries(bench_all PRIVATE tecdsa_core OpenSSL::Crypto)

# --- Tests -------------------------------------------------------------------
enable_testing()

# Helper to add a test binary that lives in tests/<name>.cpp.
function(tecdsa_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE tecdsa_core)
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

tecdsa_add_test(test_field)
tecdsa_add_test(test_sha256)
tecdsa_add_test(test_ec)
tecdsa_add_test(test_rfc6979)
tecdsa_add_test(test_ecdsa)
tecdsa_add_test(test_beaver)
tecdsa_add_test(test_paillier)

# --- OpenSSL interop tests (Interim Report sec. 4.2.2) -----------------------
# Sign with our pipeline (standard or threshold), verify with OpenSSL:
# strongest correctness check, proves bit-for-bit interoperability.
tecdsa_add_test(test_openssl_interop)
target_link_libraries(test_openssl_interop PRIVATE OpenSSL::Crypto)
tecdsa_add_test(test_tecdsa)
target_link_libraries(test_tecdsa PRIVATE OpenSSL::Crypto)
