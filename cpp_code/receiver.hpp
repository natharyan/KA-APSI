#ifndef RECEIVER_HPP
#define RECEIVER_HPP

#include <vector>
#include <cstddef>
#include "helpers.hpp"

// TODO: Add @brief

class Receiver {
public:
    uint256_t merkle_root;
    vector<vector<uint256_t>> polys;
    size_t input_len;
    vector<uint256_t> ka_messages;
    vector<uint256_t> randomness;
    vector<uint256_t> input;

    Receiver(const uint256_t *input, size_t input_len);
    void commit();
};

#endif