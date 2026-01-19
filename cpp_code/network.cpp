#include "network.hpp"

NetworkSimulator::NetworkSimulator(long lcs, long lsc, long bw)
    : latency_ms_client_to_server(lcs),
      latency_ms_server_to_client(lsc),
      bandwidth_kbps(bw) {}

long NetworkSimulator::transmit_ms_for_bytes(size_t bytes, long kbps) {
    if (kbps <= 0) return 0;
    double ms = (double)bytes * 8.0 / (double)kbps;
    return (long)std::ceil(ms);
}

void NetworkSimulator::sendClientToServer(const std::string &msg) {
    size_t bytes = msg.size();
    bytes_client_to_server += bytes;
    long ttx = transmit_ms_for_bytes(bytes, bandwidth_kbps);
    long total = latency_ms_client_to_server + ttx;
    std::this_thread::sleep_for(std::chrono::milliseconds(total));
}

void NetworkSimulator::sendServerToClient(const std::string &msg) {
    size_t bytes = msg.size();
    bytes_server_to_client += bytes;
    long ttx = transmit_ms_for_bytes(bytes, bandwidth_kbps);
    long total = latency_ms_server_to_client + ttx;
    std::this_thread::sleep_for(std::chrono::milliseconds(total));
}

size_t NetworkSimulator::totalSentBytes() const {
    return bytes_client_to_server + bytes_server_to_client;
}

size_t NetworkSimulator::totalClientToServer() const {
    return bytes_client_to_server.load();
}

size_t NetworkSimulator::totalServerToClient() const {
    return bytes_server_to_client.load();
}
