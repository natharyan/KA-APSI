#include "sender.hpp"
#include "network.hpp"
#include <random>
#include <cstring>

using std::vector;
using std::random_device;

// Sender Constructor
Sender::Sender(const uint256_t *input, size_t input_len) {
    this->input_len = input_len;
    this->input = vector<uint256_t>(input, input + input_len);
    random_values = vector<uint256_t>();
    merkle_root = uint256_t();
    merkle_leaves = vector<uint256_t>();
}

// Sender Commitment
void Sender::commit(){
    this->random_values.resize(this->input_len);
    this->merkle_leaves.resize(this->input_len);
    
    // 1. Generate input_len random field elements.
    for (size_t i = 0; i < this->input_len; i++) {
        uint8_t random_value[32];
        random_device rd;
        for (size_t j = 0; j < 32; j++) {
            random_value[j] = rd() & 0xFF;
        }
        memcpy(&this->random_values[i].bytes, random_value, 32);
    }
    
    // 2. Compute the Merkle leaves using concatenation and H_1
    for (size_t k = 0; k < this->input_len; k++) {
        // Use concatenate_and_hash which effectively does H_1(x_i || r_i)
        this->merkle_leaves[k] = concatenate_and_hash(this->input[k], this->random_values[k]);
    }
    this->merkle_root = Merkle_Root_Sender(this->merkle_leaves);
}

