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

int parse_args(int argc, char *argv[], 
    size_t &rec_sz, size_t &sen_sz, string &mode){
    if (argc < 3) {
        printf("Usage: %s <receiver_size> <sender_size> [--mode lan|wan]\n", argv[0]);
        printf("Example: %s 1000 1000 --mode wan\n", argv[0]);
        return 1;
    }

    // Parse command line arguments
    rec_sz = atoi(argv[1]);
    sen_sz = atoi(argv[2]);

    // Parse network mode
    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            mode = argv[++i];
        }
    }

    return 0;
    
}

int main(int argc, char *argv[]) {

    size_t rec_sz, sen_sz;
    string mode = "lan";
    
    // Parse Arguments
    if(parse_args(argc, argv, rec_sz, sen_sz, mode)){
        return 1;
    }
    
    random_device rd;
    vector<uint256_t> receiver_input(rec_sz);
    vector<uint256_t> sender_input(sen_sz);
    
    
    
    // Generate receiver input
    for (size_t i = 0; i < rec_sz; i++) {
        for (size_t j = 0; j < 32; j++) {
            receiver_input[i].bytes[j] = rd() & 0xFF;
        }
    }
    
    // Generate sender input (with some overlap for testing)
    for (size_t i = 0; i < sen_sz; i++) {
        if (i < rec_sz / 2) {
            // First half overlaps with receiver
            sender_input[i] = receiver_input[i];
        } else {
            // Second half is different
            for (size_t j = 0; j < 32; j++) {
                sender_input[i].bytes[j] = rd() & 0xFF; 
            }
        }
    }
    
    // Network configuration
    double lat_cs = 1.0, lat_sc = 1.0, bw_kbps = 100000; // defaults (fast LAN)
    if (mode == "wan") {
        lat_cs = 40.0;  // 80 ms round-trip time
        lat_sc = 40.0;
        // bw_kbps = 50000; // 50 Mbps
        bw_kbps = 1000; // 1 Mbps
    } else if (mode == "lan") {
        lat_cs = 0.1;
        lat_sc = 0.1;
        bw_kbps = 10000000; // 10 Gbps
    }

    printf("Receiver size: %zu, Sender size: %zu\n", rec_sz, sen_sz);
    printf("Network mode: %s\n", mode.c_str());
    NetworkSimulator net(lat_cs, lat_sc, bw_kbps);
    
    // Create instances with different inputs
    Receiver receiver(receiver_input.data(), rec_sz);
    Sender sender(sender_input.data(), sen_sz);
    
    // Both parties commit
    receiver.commit();
    sender.commit();
    
    vector<uint256_t> intersection = intersect(receiver, sender, net);

    // size_t sent_kb = (net.totalClientToServer() + net.totalServerToClient()) / 1024;
    double sent_kb_f = (double)(net.totalClientToServer() + net.totalServerToClient()) / 1024.0;
    printf("Total Comm = %.2f KB\n", sent_kb_f);
    printf("client->server bytes: %ld\n", net.totalClientToServer());
    printf("server->client bytes: %ld\n", net.totalServerToClient());

    return 0;
}