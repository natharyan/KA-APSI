#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <unordered_set>
#include <algorithm> 
#include <atomic>
#include <thread>
#include <chrono>
#include "monocypher.hpp"
#include "helpers.hpp"
#include "network.hpp"
#include "sender.hpp"
#include "receiver.hpp"
#include "intersect.hpp"

using namespace std;


vector<uint256_t> intersect(Receiver &receiver, Sender &sender, NetworkSimulator &net) {
    auto intersection_start = chrono::high_resolution_clock::now();
    
    // 1. Receiver sends polynomials to the sender
    printf("Receiver sends %zu polynomials to the sender.\n", receiver.polys.size());
    auto send_start = chrono::high_resolution_clock::now();
    for (const auto& poly : receiver.polys) {
        for (const auto& coeff : poly) {
            string coeff_str(reinterpret_cast<const char*>(coeff.bytes), 32);
            net.sendClientToServer(coeff_str);
        }
    }
    auto send_end = chrono::high_resolution_clock::now();
    auto rec_send_duration = chrono::duration_cast<chrono::microseconds>(send_end - send_start);
    
    // 2. Sender aborts if any(deg(receiver's poly)) < 1 or the Merkle root does not match
    auto sender_start = chrono::high_resolution_clock::now();
    for (const auto& poly : receiver.polys) {
        if (poly.size() < 2) {
            throw runtime_error("Sender aborts: Polynomial degree < 1");
        }
    }
    
    // check if merkle root created using receiver.polys matches with receiver.merkle_root
    uint256_t computed_root = Merkle_Root_Receiver(receiver.polys, receiver.input_len);
    if (!(computed_root == receiver.merkle_root)) {
        throw runtime_error("Sender aborts: Merkle root does not match");
    }
    printf("Receiver's input is valid. Sender proceeds.\n");

    // 3. Sender computes the number of receiver elements
    size_t num_receiver_elements = 0;
    for (const auto& poly : receiver.polys) {
        num_receiver_elements += poly.size();
    }
    if (num_receiver_elements != receiver.input_len) {
        throw runtime_error("Sender aborts: Number of receiver elements does not match");
    }
    
    // Generate sender's KA values
    uint256_t a = uint256_t();
    random_device rd;
    for (size_t j = 0; j < 32; j++) {
        a.bytes[j] = rd() & 0xFF;
    }
    uint8_t g_a[32];
    crypto_x25519_public_key(g_a, a.bytes);
    uint256_t m_sender = uint256_t();
    memcpy(m_sender.bytes, g_a, 32);

    // 4. Sender processes each input
    size_t bin_size = num_receiver_elements / log2(num_receiver_elements);
    vector<vector<uint256_t>> T_Sender(bin_size);
    vector<uint256_t> k_values;
    k_values.reserve(sender.input_len);
    
    for (size_t idx = 0; idx < sender.input_len; idx++) {
        const auto& message = sender.input[idx];
        
        // Get bin index using H_1(message)
        uint256_t h1_message = H_1(message);
        uint8_t hash[32];
        crypto_blake2b(hash, sizeof(hash), h1_message.bytes, 32);
        size_t bin_index = H_bin(hash, bin_size);
        
        // Find the corresponding polynomial
        if (bin_index >= receiver.polys.size()) {
            throw runtime_error("Bin index out of range");
        }
        
        // Evaluate polynomial at H_1(message)
        uint256_t poly_eval = evaluate_poly(receiver.polys[bin_index], h1_message.bytes);
        
        // Compute shared key
        uint256_t shared_key;
        crypto_x25519(shared_key.bytes, a.bytes, poly_eval.bytes);
        uint256_t k_i;
        crypto_blake2b(k_i.bytes, sizeof(k_i.bytes), shared_key.bytes, sizeof(shared_key.bytes));
        
        k_values.push_back(k_i);
        T_Sender[bin_index].push_back(message);
    }

    // 5. Sender computes P_j polynomials for each bin
    vector<vector<uint256_t>> P_Sender(bin_size);
    size_t k_i_counter = 0;
    for (size_t i = 0; i < T_Sender.size(); ++i) {
        if (T_Sender[i].size() == 1) {
            // Find the next bin with at least 1 element (not itself)
            size_t j = (i + 1) % T_Sender.size();
            while (j != i && T_Sender[j].empty()) {
                j = (j + 1) % T_Sender.size();
            }
            // Move the element
            T_Sender[j].push_back(T_Sender[i][0]);
            T_Sender[i].clear();
        }
    }   
    for (size_t i = 0; i < bin_size; i++) {
        if (T_Sender[i].empty()) {
            continue;
        }
        
        vector<uint256_t> H_2_values;
        vector<uint256_t> r_values;
        
        for (size_t j = 0; j < T_Sender[i].size(); j++) {
            uint256_t k_i = k_values[k_i_counter];
            H_2_values.push_back(H_2(T_Sender[i][j], k_i));
            r_values.push_back(sender.random_values[k_i_counter]);
            k_i_counter++;
        }
        
        P_Sender[i] = Lagrange_Polynomial(H_2_values, r_values);
    }
    
    printf("Sender sends %zu polynomials, m, and D' to the receiver.\n", P_Sender.size());
    
    // Send polynomials
    for (const auto& poly : P_Sender) {
        for (const auto& coeff : poly) {
            string coeff_str(reinterpret_cast<const char*>(coeff.bytes), 32);
            net.sendServerToClient(coeff_str);
        }
    }
    
    // Send m_sender
    string m_sender_str(reinterpret_cast<const char*>(m_sender.bytes), 32);
    net.sendServerToClient(m_sender_str);
    
    // Send merkle leaves
    for (const auto& leaf : sender.merkle_leaves) {
        string leaf_str(reinterpret_cast<const char*>(leaf.bytes), 32);
        net.sendServerToClient(leaf_str);
    }
    auto sender_end = chrono::high_resolution_clock::now();

    // 6. Receiver computes intersection
    auto receiver_start2 = chrono::high_resolution_clock::now();
    
    // Verify sender's merkle root
    if (!(sender.merkle_root == Merkle_Root_Sender(sender.merkle_leaves))) {
        throw runtime_error("Receiver aborts: Merkle root does not match");
    }
    printf("Sender's input is valid. Receiver proceeds.\n");

    vector<uint256_t> R_intersection;
    for (size_t i = 0; i < receiver.input_len; i++) {
        // Get bin index using H_1(input)
        uint256_t h1_input = H_1(receiver.input[i]);
        uint8_t hash[32];
        crypto_blake2b(hash, sizeof(hash), h1_input.bytes, 32);
        size_t bin_index = H_bin(hash, bin_size);
        
        // Compute shared key using receiver's randomness
        uint256_t b_i = receiver.randomness[i];
        uint256_t shared_key;
        crypto_x25519(shared_key.bytes, b_i.bytes, m_sender.bytes);
        uint256_t k_i_receiver;
        crypto_blake2b(k_i_receiver.bytes, sizeof(k_i_receiver.bytes), shared_key.bytes, sizeof(shared_key.bytes));
        
        // Evaluate sender's polynomial
        uint256_t h2_input_key = H_2(receiver.input[i], k_i_receiver);
        uint256_t r_i_receiver = evaluate_poly(P_Sender[bin_index], h2_input_key.bytes);
        
        // Compute the final value for intersection check
        uint256_t final_val = concatenate_and_hash(receiver.input[i], r_i_receiver);
        R_intersection.push_back(final_val);
    }

    // Find intersection
    unordered_set<uint256_t> merkle_set(sender.merkle_leaves.begin(), sender.merkle_leaves.end());
    vector<uint256_t> intersection;
    intersection.reserve(min(R_intersection.size(), sender.merkle_leaves.size()));
    
    for (const auto& item : R_intersection) {
        if (merkle_set.count(item)) {
            intersection.push_back(item);
        }
    }
    
    auto receiver_end2 = chrono::high_resolution_clock::now();
    auto intersection_end = chrono::high_resolution_clock::now();
    
    // Calculate timings
    auto receiver_time = chrono::duration_cast<chrono::microseconds>(receiver_end2 - receiver_start2);
    auto sender_time = chrono::duration_cast<chrono::microseconds>(sender_end - sender_start);
    auto total_time = chrono::duration_cast<chrono::microseconds>(intersection_end - intersection_start);
    
    auto total_receiver_time = receiver_time + rec_send_duration;
    
    printf("\nIntersection Phase Runtime:\n");
    printf("Receiver runtime: %.3fms\n", total_receiver_time.count() / 1000.0);
    printf("Sender runtime: %.3fms\n", sender_time.count() / 1000.0);
    printf("Total runtime: %.3fms\n\n", total_time.count() / 1000.0);
    
    return intersection;
}
