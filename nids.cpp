#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Defines the libpcap API (pcap_loop, etc.)
// Defines standard I/O streams (std::cout, std::cerr)
// Defines struct for IPv4 header (ip_hdr)
// Defines struct for TCP header (tcphdr)
// Defines struct for Ethernet header (ether_header) + constants
// Defines struct for in_addr and in_addrlen for addresses
// Defines inet_ntop and byte-order helper for addresses

// Define constants
#define ETHER_HDR_LEN 14
#define SNAP_LEN 65536

// A user data struct to pass to the handler
struct PacketHandlerData {
    int packet_count = 0;
};

// Sets the Ethernet header to start at the beginning of the packet
// const is important here to signify that this function will not change the packet
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PacketHandlerData* data = reinterpret_cast<PacketHandlerData*>(user);
    
    // Check minimum packet size for Ethernet + IP headers
    if (pkthdr->caplen < ETHER_HDR_LEN + sizeof(struct ip)) {
        return;
    }

    // Increment packet count and print a message
    data->packet_count++;

    // Sets the Ethernet header to start at the beginning of the packet
    const struct ether_header *eth_header = reinterpret_cast<const struct ether_header *>(packet);
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // Move along the actual bytes of the packet (skip the ethernet header) to IP
    const struct ip *ip_header = reinterpret_cast<const struct ip *>(packet + ETHER_HDR_LEN);
    
    // Check if the IP protocol is TCP
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    // Convert source and destination IP addresses to string
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip_header->ip_src, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip, INET_ADDRSTRLEN);

    int ip_header_len = ip_header->ip_hl * 4;
    const u_char *tcp_start = packet + ETHER_HDR_LEN + ip_header_len;

    const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(tcp_start);

    std::cout << "Current Packet: " << data->packet_count
              << " | Source IP: " << source_ip
              << " | Destination IP: " << dest_ip 
	      << " | Source Port: " << ntohs(tcp_header->th_sport)
	      << " | Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    PacketHandlerData data;

    // Default interface - can be overridden by command line argument
    const char* interface = "en0";  // Default for macOS
    if (argc > 1) {
        interface = argv[1];
    }

    // Open the network interface for live capture
    handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);

    // Check for errors when opening the interface
    if (handle == nullptr) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Listening on interface " << interface << "..." << std::endl;

    // Start the packet capture loop
    pcap_loop(handle, 0, reinterpret_cast<pcap_handler>(packet_handler), reinterpret_cast<u_char*>(&data));

    // Close the pcap handle
    pcap_close(handle);

    return 0;
}
