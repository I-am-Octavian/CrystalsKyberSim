#ifndef KYBER_UTILS_H
#define KYBER_UTILS_H

#include <vector>
#include <string>
#include <cstdint>
#include <utility> // for std::pair
#include <chrono> // For timestamps

extern "C"
{
#include "api.h"
}

namespace Kyber {

    // Basic Types (Placeholders - adjust size/type based on actual Kyber spec)
    using Polynomial = std::vector<int>;      // Represents a polynomial R_q
    using Matrix = std::vector<Polynomial>; // Represents a matrix (e.g., A, pk, sk as vectors of Polynomials)
                                            // Or: using Matrix = std::vector<std::vector<Polynomial>> for A?
                                            // Let's assume A is std::vector<std::vector<int>> for simplicity in stubs.
    using Matrix2x2 = std::vector<std::vector<int>>; // Specific 2x2 matrix
    using Timestamp = std::chrono::time_point<std::chrono::system_clock>;

    // Constants (Placeholder)
    const size_t POLYNOMIAL_SIZE = 256; // Example size n
    const size_t K = 2;                 // Example dimension k for Kyber512
    const int Q = 3329;               // Example modulus q

    // --- Core Kyber-like Functions (Placeholders) ---

    // G: Seed expansion d -> (rho, sigma)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> G(const std::vector<uint8_t>& d);

    // Sampling functions (using seed is complex for stubs, ignoring seed input for now)
    Polynomial SampleB3(size_t size, const std::vector<uint8_t>& seed);
    Polynomial SampleB2(size_t size, const std::vector<uint8_t>& seed);

    // Generate matrix A from seed rho
    Matrix2x2 GenerateA(const std::vector<uint8_t>& rho);

    // Polynomial Arithmetic (Modulo Q omitted in stubs)
    Polynomial PolyAdd(const Polynomial& a, const Polynomial& b);
    Polynomial PolySub(const Polynomial& a, const Polynomial& b);
    Polynomial PolyScalarMul(int scalar, const Polynomial& p);

    // Matrix/Vector Operations (Modulo Q omitted in stubs)
    // Assuming A is 2x2, r is size 2 Polynomial vector -> result size 2 Polynomial vector
    Polynomial MatrixVecMul(const Matrix2x2& A, const Polynomial& r);
    // Assuming A is 2x2, r is size 2 Polynomial vector -> result size 2 Polynomial vector
    Polynomial MatrixTransposeVecMul(const Matrix2x2& A, const Polynomial& r);
    // Assuming pkT is size 2 Polynomial vector, r is size 2 Polynomial vector -> result size 1 Polynomial (scalar)
    Polynomial VecTransposeVecMul(const Polynomial& pkT, const Polynomial& r);

    Polynomial ToPoly(const std::vector<uint8_t>& vec);

    std::vector<uint8_t> ToBytes(const Polynomial& vec);

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> GenerateKeyPair();

    std::vector<uint8_t> Encrypt(Polynomial pk, std::vector<uint8_t> secret);
    std::vector<uint8_t> Decrypt(Polynomial sk, std::vector<uint8_t> cipher);


    std::vector<uint8_t> GetRhoFromPk(const std::vector<uint8_t>& pk);


    // Compression/Decompression (Placeholders)
    // Decompress bytes to a Polynomial (e.g., for RAND)
    Polynomial Decompressq(const std::vector<uint8_t>& input, int parameter);
    // Compress a Polynomial to bytes (e.g., for RAND')
    std::vector<uint8_t> Compressq(const Polynomial& input, int parameter);

    // --- 5G Protocol Specific Functions (Placeholders) ---

    // Key Derivation Function
    std::vector<uint8_t> KDF(const std::vector<uint8_t>& input);
    // Overload for KDF with key (needed for RES*, K_RAN)
    std::vector<uint8_t> KDF(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);

    // SUCI Encryption/Decryption
    std::vector<uint8_t> EMSK(const std::vector<uint8_t>& input); // Encrypt SUPI||SQN
    std::vector<uint8_t> DMSK(const std::vector<uint8_t>& input); // Decrypt C2

    // MAC Functions (using long-term key K)
    std::vector<uint8_t> f1K(const std::string& key, const std::vector<uint8_t>& input); // MAC calculation
    std::vector<uint8_t> f1_star_K(const std::string& key, const std::vector<uint8_t>& input); // MACS calculation

    // Key Generation Functions (using long-term key K)
    std::vector<uint8_t> f2K(const std::string& key, const std::vector<uint8_t>& input); // RES generation
    std::vector<uint8_t> f3K(const std::string& key, const std::vector<uint8_t>& input); // CK generation
    std::vector<uint8_t> f4K(const std::string& key, const std::vector<uint8_t>& input); // IK generation

    // --- New Functions for UAV Protocol ---

    // Symmetric Encryption/Decryption (Placeholder using simple XOR)
    std::vector<uint8_t> EncryptSymmetric(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
    std::vector<uint8_t> DecryptSymmetric(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext);

    // Temporary Identity Generation (Placeholder)
    std::string GenerateTID(const std::string& prefix);

    // Timestamp Generation and Validation (Placeholder)
    Timestamp GenerateTST(int validity_seconds);
    bool ValidateTST(const Timestamp& tst);

    // --- Helper Functions ---
    std::vector<uint8_t> U64ToBytes(uint64_t val);
    uint64_t BytesToU64(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> ConcatBytes(const std::vector<std::vector<uint8_t>>& vecs);
    std::vector<uint8_t> PolyToBytes(const Polynomial& p);
    Polynomial BytesToPoly(const std::vector<uint8_t>& bytes, size_t expected_size);
    std::vector<uint8_t> StringToBytes(const std::string& str);
    std::string BytesToString(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> TimestampToBytes(const Timestamp& t);
    Timestamp BytesToTimestamp(const std::vector<uint8_t>& bytes);

} // namespace Kyber

#endif // KYBER_UTILS_H
