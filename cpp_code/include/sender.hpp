#ifndef SENDER_HPP
#define SENDER_HPP

#include "helpers.hpp"
#include <vector>
#include <cstddef>

// TODO: Add @brief

// Forward declarations
class Receiver;
struct NetworkSimulator;

class Sender {
private:
    size_t input_len;
    std::vector<uint256_t> input;
    std::vector<uint256_t> random_values;
    friend std::vector<uint256_t> intersect(Receiver &receiver, Sender &sender, NetworkSimulator &net);

public:
    uint256_t merkle_root;
    std::vector<uint256_t> merkle_leaves;

    Sender(const uint256_t *input, size_t input_len);
    void commit();
};

#endif