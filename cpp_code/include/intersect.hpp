#ifndef INTERSECT_HPP
#define INTERSECT_HPP

#include <vector>
#include "helpers.hpp"

// Forward declarations
class Receiver;
class Sender;
struct NetworkSimulator;

// TODO: Add @brief
/**
 * @param receiver The Receiver instance (must have called commit())
 * @param sender The Sender instance (must have called commit())
 * @param net The network simulator for communication
 * @return Vector of intersection elements
 */
std::vector<uint256_t> intersect(Receiver &receiver, Sender &sender, NetworkSimulator &net);

#endif
