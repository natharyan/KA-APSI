#ifndef NETWORK_HPP
#define NETWORK_HPP
#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <cmath>

// TODO: Add @brief

struct NetworkSimulator {
    // latency in ms, bandwidth in kilobits per second (kbps)
    long latency_ms_client_to_server = 1;
    long latency_ms_server_to_client = 1;
    long bandwidth_kbps = 50000;

    std::atomic<size_t> bytes_client_to_server{0};
    std::atomic<size_t> bytes_server_to_client{0};

    NetworkSimulator() = default;
    NetworkSimulator(long lcs, long lsc, long bw);

    // compute transmission delay in ms given bytes and bandwidth (kbps).
    static long transmit_ms_for_bytes(size_t bytes, long kbps);

    // simulate sending from client to server: blocks for latency+transmit and increments counters.
    void sendClientToServer(const std::string &msg);

    // simulate sending from server to client
    void sendServerToClient(const std::string &msg);

    // helpers to read totals (in bytes)
    size_t totalSentBytes() const;
    size_t totalClientToServer() const;
    size_t totalServerToClient() const;
};

#endif
