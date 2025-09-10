#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <vector>
#include "monocypher.hpp"

using namespace std;
using namespace NTL;

// Array of 32 elements of 8 bits each
struct uint256_t {
    uint8_t bytes[32];
};

// Function to generate randomness and Elligator messages
// Input: number of KA messages to generate.
pair<vector<uint256_t>, vector<uint256_t>> gen_elligator_messages(size_t num_messages);

size_t H_bin(const uint8_t hash[32], size_t bin_size);

uint256_t H_2(const uint256_t& x_i, const uint256_t& k_i);

ZZ bytes_to_ZZ(const uint256_t& num); 

uint256_t ZZ_to_bytes(const ZZ& num); 

vector<uint256_t> Lagrange_Polynomial(vector<uint256_t> inputs, const vector<uint256_t> evaluations);

void test_interpolation_result(const vector<uint256_t>& coeffs,
                              const vector<uint256_t>& x,
                              const vector<uint256_t>& y); 

uint256_t combine_hashes(const uint256_t& left, const uint256_t& right); 

uint256_t bytes_to_field(const uint8_t* bytes); 

uint256_t Merkle_Root_Receiver(vector<vector<uint256_t>> merkle_leaves, size_t n);

// Compute the Merkle root after appending input values with the ideal permutation of the random values
uint256_t Merkle_Root_Sender(vector<uint256_t> merkle_leaves);

uint256_t evaluate_poly(const vector<uint256_t>& poly, const uint8_t* point_bytes); 

uint256_t H_1(const uint256_t& x);
uint256_t concatenate_and_hash(const uint256_t& a, const uint256_t& b);

inline bool operator==(const uint256_t& a, const uint256_t& b) {
    return memcmp(a.bytes, b.bytes, 32) == 0;
}

namespace std {
    template <>
    struct hash<uint256_t> {
        size_t operator()(const uint256_t& k) const {
            uint8_t digest[32];
            // TODO: check if this can be optimized
            crypto_blake2b(digest, sizeof(digest), k.bytes, 32);
            size_t h;
            memcpy(&h, digest, sizeof(h));
            return h;
        }
    };
}