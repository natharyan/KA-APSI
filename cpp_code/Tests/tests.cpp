#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include "../monocypher.hpp"

int test_elligator() {
    // Step 1: Generate a random scalar b (32 bytes)
    uint8_t scalar[32];
    std::random_device rd;
    for (size_t i = 0; i < 32; i++) {
        scalar[i] = rd() & 0xFF;
    }

    // Step 2: Compute g^b using X25519 (public key = base^b)
    uint8_t g_b[32]; // g^b
    crypto_x25519_public_key(g_b, scalar);

    std::cout << "Original g^b: ";
    for (int i = 0; i < 32; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)g_b[i];
    std::cout << std::endl;

    // Step 3: Elligator encoding (forward map)
    uint8_t encoded[32];
    crypto_elligator_map(encoded, g_b);

    std::cout << "Elligator encoding: ";
    for (int i = 0; i < 32; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)encoded[i];
    std::cout << std::endl;

    // Step 4: Elligator decoding (reverse map)
    uint8_t decoded[32];
    uint8_t tweak = 0; // tweak can be 0 or 1 to handle sign ambiguity
    int res = crypto_elligator_rev(decoded, encoded, tweak);

    if (res != 0) {
        std::cerr << "Elligator reverse map failed!" << std::endl;
        return 1;
    }

    std::cout << "Decoded g^b: ";
    for (int i = 0; i < 32; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)decoded[i];
    std::cout << std::endl;

    // Step 5: Verify equality
    if (std::memcmp(g_b, decoded, 32) == 0) {
        std::cout << "Success: decoded g^b matches original g^b!" << std::endl;
    } else {
        std::cout << "Error: decoded g^b does NOT match original g^b!" << std::endl;
    }

    return 0;
}

int main() {
    return test_elligator();
}