#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <vector>
#include <sstream>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include "monocypher.hpp"
#include "helpers.hpp"

using namespace std;
using namespace NTL;

pair<vector<uint256_t>, vector<uint256_t>> gen_elligator_messages(size_t num_messages) {
    vector<uint256_t> messages(num_messages);
    vector<uint256_t> randomness(num_messages);
    for (size_t i = 0; i < num_messages; i++) {
        uint8_t b_i[32];
        random_device rd;
        for (size_t j = 0; j < 32; j++) {
            b_i[j] = rd() & 0xFF;
        }
        // Compute g^b using X25519
        uint8_t g_b[32];
        crypto_x25519_public_key(g_b, b_i);
        // Elligator encoding
        uint8_t encoded[32];
        crypto_elligator_map(encoded, g_b);

        memcpy(&messages[i], encoded, 32);
        memcpy(&randomness[i], b_i, 32);
    }
    return make_pair(messages, randomness);
}

// Hash elements to bin indices in [0,n/log(n)-1], where n is the input size of the receiver
size_t H_bin(const uint8_t hash[32], size_t bin_size) {
    uint64_t bin_index;
    memcpy(&bin_index, hash, sizeof(bin_index));
    return bin_index % bin_size;
}

uint256_t H_2(const uint256_t& x_i, const uint256_t& k_i) {
    // Concatenate x_i and k_i
    uint8_t input[64];
    memcpy(input, x_i.bytes, 32);
    memcpy(input + 32, k_i.bytes, 32);
    
    // Hash the concatenation
    uint256_t result;
    crypto_blake2b(result.bytes, sizeof(result.bytes), input, sizeof(input));
    return result;
}

ZZ bytes_to_ZZ(const uint256_t& num) {
    ZZ result = ZZ(0);
    ZZ base = ZZ(1);
    
    for (int i = 0; i < 32; i++) {
        result += ZZ(num.bytes[i]) * base;
        base *= 256;
    }
    
    return result;
}

uint256_t ZZ_to_bytes(const ZZ& num) {
    ZZ prime = conv<ZZ>("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    uint256_t result;
    memset(result.bytes, 0, 32);

    ZZ temp = num % prime;
    if (temp < 0) temp += prime;

    for (int i = 0; i < 32 && temp > 0; i++) {
        result.bytes[i] = to_long(temp % 256);
        temp /= 256;
    }

    return result;
}

vector<uint256_t> Lagrange_Polynomial(vector<uint256_t> inputs,
                                      const vector<uint256_t> evaluations) {
    size_t n = inputs.size();
    if (n == 0 || n != evaluations.size()) {
        throw runtime_error("Invalid input for Lagrange interpolation");
    }
    
    if (n < 2) {
        throw runtime_error("Need at least 2 points for meaningful interpolation");
    }
    
    // Prime field
    ZZ prime = conv<ZZ>("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    ZZ_p::init(prime);
    
    vec_ZZ_p zp_inputs, zp_evals;
    zp_inputs.SetLength(n);
    zp_evals.SetLength(n);
    
    for (size_t i = 0; i < n; i++) {
        ZZ temp_input = bytes_to_ZZ(inputs[i]) % prime;
        if (temp_input < 0) temp_input += prime;
        zp_inputs[i] = to_ZZ_p(temp_input);
        
        ZZ temp_eval = bytes_to_ZZ(evaluations[i]) % prime;
        if (temp_eval < 0) temp_eval += prime;
        zp_evals[i] = to_ZZ_p(temp_eval);
    }
    
    //check for duplicate x-coordinates
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (zp_inputs[i] == zp_inputs[j]) {
                throw runtime_error(
                    "Duplicate x-coordinate detected at positions " + 
                    to_string(i) + " and " + to_string(j)
                );
            }
        }
    }
    //using ntl's interpolation
    ZZ_pX P;
    interpolate(P, zp_inputs, zp_evals);
    
    long degree = deg(P);
    // cout << "Polynomial degree: " << degree << endl;
    
    if (degree < 0) {
        vector<uint256_t> result(2);
        result[0] = evaluations[0]; 
        memset(result[1].bytes, 0, 32);
        // cout << "Created fallback degree-1 polynomial" << endl;
        return result;
    }
    
    vector<uint256_t> result(degree + 1);
    
    for (long i = 0; i <= degree; i++) {
        ZZ coeff_zz = rep(coeff(P, i));
        result[i] = ZZ_to_bytes(coeff_zz);
    }
    
    // cout << "Generated polynomial with " << result.size() << " coefficients" << endl;
    return result;
}
void test_interpolation_result(const vector<uint256_t>& coeffs,
                              const vector<uint256_t>& x,
                              const vector<uint256_t>& y) {
    // cout << "Testing result polynomial" << endl;

    ZZ prime = conv<ZZ>("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    ZZ_p::init(prime);

    ZZ_pX P;
    for (size_t j = 0; j < coeffs.size(); j++) {
        ZZ temp_coeff = bytes_to_ZZ(coeffs[j]);
        SetCoeff(P, j, to_ZZ_p(temp_coeff));         
    }

    for (size_t i = 0; i < x.size(); i++) {
        ZZ temp_x = bytes_to_ZZ(x[i]);
        ZZ_p zp_x = to_ZZ_p(temp_x);

        ZZ_p res = eval(P, zp_x);                    
        ZZ result_zz = rep(res);
        uint256_t result = ZZ_to_bytes(result_zz);

        if (memcmp(result.bytes, y[i].bytes, 32) != 0){
            cout << "Error! x = " << bytes_to_ZZ(x[i]) 
                << ", expected y = " << bytes_to_ZZ(y[i]) 
                << ", got y = " << bytes_to_ZZ(result) << endl;
            return;
        }
    }

    cout << "Polynomial is interpolated correctly!" << endl;
}

//to convert bytes to field element
uint256_t bytes_to_field(const uint8_t* bytes) {
    uint256_t result;
    memcpy(result.bytes, bytes, 32);
    return result;
}


// Compute all n-th roots of unity in the field
vector<ZZ_p> compute_roots_of_unity(size_t n) {
    ZZ prime = conv<ZZ>("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    ZZ_p::init(prime);

    // Find a generator g of the multiplicative group
    ZZ_p g = ZZ_p(3);

    // Compute g^((p-1)/n)
    ZZ exp = (prime - 1) / n;
    ZZ_p root = power(g, exp);

    std::vector<ZZ_p> roots(n);
    roots[0] = ZZ_p(1);
    for (size_t i = 1; i < n; ++i) {
        roots[i] = roots[i-1] * root;
    }
    return roots;
}

// Evaluate a polynomial (coeffs) at a field element (x)
uint256_t eval_poly_coeffs(vector<uint256_t>& coeffs, const ZZ_p& x) {
    ZZ prime = conv<ZZ>("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    ZZ_p::init(prime);
    ZZ_pX P;
    for (size_t i = 0; i < coeffs.size(); ++i) {
        SetCoeff(P, i, to_ZZ_p(bytes_to_ZZ(coeffs[i]) % prime));
    }
    ZZ_p val = eval(P, x);
    return ZZ_to_bytes(rep(val));
}

// Merkle root on evaluations at roots of unity
uint256_t Merkle_Root_Receiver(vector<vector<uint256_t>> polys, size_t n) {
    if (polys.empty() || n == 0) {
        uint256_t zero;
        memset(zero.bytes, 0, 32);
        return zero;
    }

    // 1. Compute all n-th roots of unity
    std::vector<ZZ_p> roots = compute_roots_of_unity(n);

    // 2. Evaluate polynomials at consecutive roots of unity
    std::vector<uint256_t> merkle_leaves;
    size_t root_idx = 0;
    for (auto& poly : polys) {
        size_t deg = poly.size();
        for (size_t j = 0; j < deg; ++j) {
            if (root_idx >= n) break;
            uint256_t eval = eval_poly_coeffs(poly, roots[root_idx]);
            // Hash the evaluation to get the leaf
            uint256_t leaf_hash;
            crypto_blake2b(leaf_hash.bytes, 32, eval.bytes, 32);
            merkle_leaves.push_back(leaf_hash);
            ++root_idx;
        }
    }
    // Safety check
    if (merkle_leaves.size() != n) {
        throw std::runtime_error("Total number of evaluations does not match n");
    }

    // 3. Build Merkle tree as before
    std::vector<uint256_t> current_level = merkle_leaves;
    while (current_level.size() > 1) {
        std::vector<uint256_t> next_level;
        for (size_t i = 0; i < current_level.size(); i += 2) {
            if (i + 1 < current_level.size()) {
                next_level.push_back(H_2(current_level[i], current_level[i + 1]));
            } else {
                next_level.push_back(H_2(current_level[i], current_level[i]));
            }
        }
        current_level = next_level;
    }
    return current_level[0];
}

// Takes as input the merkle leaves and return the merkle root.
uint256_t Merkle_Root_Sender(vector<uint256_t> merkle_leaves) {
    vector<uint256_t> current_level = merkle_leaves;
    
    while (current_level.size() > 1) {
        vector<uint256_t> next_level;
        
        for (size_t i = 0; i < current_level.size(); i += 2) {
            if (i + 1 < current_level.size()) {
                next_level.push_back(H_2(current_level[i], current_level[i + 1]));
            } else {
                next_level.push_back(H_2(current_level[i], current_level[i]));
            }
        }
        
        current_level = next_level;
    }
    
    return current_level[0];
}

uint256_t evaluate_poly(const vector<uint256_t>& poly, const uint8_t* point_bytes) {
    if (poly.empty()) {
        uint256_t zero;
        memset(zero.bytes, 0, 32);
        return zero;
    }
    
    //same prime as lagrange 
    ZZ prime = conv<ZZ>("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    ZZ_p::init(prime);
    
    //reconstructing polynomial from coefficients
    ZZ_pX P;
    for (size_t i = 0; i < poly.size(); i++) {
        ZZ coeff_zz = bytes_to_ZZ(poly[i]) % prime;
        if (coeff_zz < 0) coeff_zz += prime;
        SetCoeff(P, i, to_ZZ_p(coeff_zz));
    }
    
    //convert point_bytes to uint256_t first, then to ZZ
    uint256_t point;
    memcpy(point.bytes, point_bytes, 32);
    
    ZZ point_zz = bytes_to_ZZ(point) % prime;
    if (point_zz < 0) point_zz += prime;
    ZZ_p point_zp = to_ZZ_p(point_zz);
    
    //evaluate polynomial at the point
    ZZ_p result_zp = eval(P, point_zp);
    ZZ result_zz = rep(result_zp);
    
    return ZZ_to_bytes(result_zz);
}

// H_1 hash function for single input
uint256_t H_1(const uint256_t& x) {
    uint256_t result;
    crypto_blake2b(result.bytes, sizeof(result.bytes), x.bytes, 32);
    return result;
}

// Concatenation and hash function for two uint256_t values  
uint256_t concatenate_and_hash(const uint256_t& a, const uint256_t& b) {
    uint8_t input[64];
    memcpy(input, a.bytes, 32);
    memcpy(input + 32, b.bytes, 32);
    
    uint256_t result;
    crypto_blake2b(result.bytes, sizeof(result.bytes), input, sizeof(input));
    return result;
}