extern "C" {
    #include <pcap.h>
}
#include <iostream>

int packet_count = 0;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_count++;
    std::cout << "Captured packet #" << packet_count 
              << " length: " << header->len << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Starting capture on en0..." << std::endl;
    pcap_loop(handle, 10, packet_handler, nullptr); // capture 10 packets

    pcap_close(handle);
    return 0;
}

