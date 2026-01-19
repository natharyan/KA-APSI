#include "receiver.hpp"

// Receiver Constructor
Receiver::Receiver(const uint256_t *input, size_t input_len) {
    this->input = vector<uint256_t>(input, input + input_len);
    this->input_len = input_len;

    ka_messages = vector<uint256_t>();
    polys = vector<vector<uint256_t>>();
    merkle_root = uint256_t();
}

// Receiver commitment
void Receiver::commit(){

    // 1. Generate KA messages.
    this->ka_messages.resize(this->input_len);
    tie(this->ka_messages, this->randomness) = gen_elligator_messages(this->input_len);
    
    // 2. Create uniform hashing table.
    size_t bin_size = this->input_len / log2(this->input_len); // n/log(n)
    vector<vector<uint256_t>> T_Rec(bin_size);
    
    // Hash each input message and place it into the correct bin using H_1(input)
    for (const auto& current_message : this->input) {
        uint8_t hash[32];

        uint256_t h1_message = H_1(current_message);
        crypto_blake2b(hash, sizeof(hash), h1_message.bytes, 32);

        size_t bin_index = H_bin(hash, bin_size);
        T_Rec[bin_index].push_back(current_message);
    }
    
    // 3. Create polynomials using (H_1(y_i), ka_message_i) pairs
    size_t ka_counter = 0;
    for (size_t i = 0; i < bin_size; i++) {

        const auto& bin_elements = T_Rec[i];
        if (bin_elements.empty()) continue;
    
        vector<uint256_t> H1_values;
        vector<uint256_t> ka_messages_for_bin;

        for (const auto& element : bin_elements) {
            H1_values.push_back(H_1(element)); // H_1(y_i)
            ka_messages_for_bin.push_back(this->ka_messages[ka_counter]);
            ka_counter++;
        }

        this->polys.push_back(Lagrange_Polynomial(H1_values, ka_messages_for_bin));
    }

    // 4. Merkle tree root using the evaluations at roots of unity.
    this->merkle_root = Merkle_Root_Receiver(this->polys, this->input_len);
}
