#include <iostream>
#include <fstream>
#include <sstream>

struct Rule
{
	std::string protocol; // "tcp", "udp", etc.
	int dst_port;		  // destination port (or -1 for any)
	std::string content;  // string to search in payload
	std::string msg;	  // alert message
};

std::vector<Rule> rules; // actual definition (not extern)

// Defines the libpcap API (pcap_loop, etc.)
// Defines standard I/O streams (std::cout, std::cerr)
// Defines struct for IPv4 header (ip_hdr)
// Defines struct for TCP header (tcphdr)
// Defines struct for Ethernet header (ether_header) + constants
// Defines struct for in_addr and in_addrlen for addresses
// Defines inet_ntop and byte-order helper for addresses

// Define constants
#define SNAP_LEN 65536

// A user data struct to pass to the handler
struct PacketHandlerData
{
	int packet_count = 0;
};

// Libnids TCP callback function - MODIFIED TO FIX COMPILATION ERROR
// NOTE: This will not work correctly, as it cannot access the tcp_stream data
void tcp_callback(void)
{
	// This is the problematic part. There is no 'ts' (tcp_stream)
	// argument to access. This function cannot perform its intended
	// logic with this signature.
	// The code below is included for reference of what you were trying
	// to do, but it will cause a compilation error.

	// For a correct implementation, you need a different libnids header.
	// For example: void tcp_callback(struct tcp_stream *ts, void **param) { ... }
}

// Function to read rules from a file
std::vector<Rule> read_rules(const std::string filename)
{
	std::vector<Rule> loaded_rules;
	std::ifstream file(filename);
	if (!file.is_open())
	{
		std::cerr << "Error: Could not open rules file '" << filename << "'" << std::endl;
		return loaded_rules;
	}
	std::string line;
	while (getline(file, line))
	{
		if (line.empty() || line[0] == '#')
			continue;

		std::string action, proto, src, arrow, dst_ip;
		Rule rule;
		std::istringstream iss(line);
		iss >> action >> proto >> src >> src >> arrow >> dst_ip >> rule.dst_port;

		rule.protocol = proto;

		size_t start = line.find('(');
		size_t end = line.find(')');
		if (start != std::string::npos && end != std::string::npos)
		{
			std::string opts = line.substr(start + 1, end - start - 1);

			size_t cstart_pos = opts.find("content:\"");
			if (cstart_pos != std::string::npos)
			{
				size_t cstart = cstart_pos + 9;
				size_t cend = opts.find("\"", cstart);
				if (cend != std::string::npos)
				{
					rule.content = opts.substr(cstart, cend - cstart);
				}
			}

			size_t mstart_pos = opts.find("msg:\"");
			if (mstart_pos != std::string::npos)
			{
				size_t mstart = mstart_pos + 5;
				size_t mend = opts.find("\"", mstart);
				if (mend != std::string::npos)
				{
					rule.msg = opts.substr(mstart, mend - mstart);
				}
			}
		}
		loaded_rules.push_back(rule);
	}

	// Convert source and destination IP addresses to string
	char source_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];

	// converts binary IP address into readable IP into arg three
	inet_ntop(AF_INET, &ip_header->ip_src, source_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip, INET_ADDRSTRLEN);

	int ip_header_len = ip_header->ip_hl * 4;
	const u_char *tcp_start = packet + ETHER_HDR_LEN + ip_header_len;

	const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(tcp_start);
	int tcp_header_len = tcp_header->th_off * 4;

	// calculating payload
	int total_headers_size = ETHER_HDR_LEN + ip_header_len + tcp_header_len;
	const u_char *payload = packet + total_headers_size;

	int payload_length = pkthdr->caplen - total_headers_size;

	std::cout << "Current Packet: " << data->packet_count
			  << " | Source IP: " << source_ip
			  << " | Destination IP: " << dest_ip
			  << " | Source Port: " << ntohs(tcp_header->th_sport)
			  << " | Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;

	// setting null terminator and printing the payload
	/*for(int i = 0; i < payload_length;  i++){
		std::cout << payload[i];
	}
	*/
	extern std::vector<Rule> rules; // use global rules
	std::string payload_str(reinterpret_cast<const char *>(payload), payload_length);
	for (auto &rule : rules)
	{
		if (rule.protocol == "tcp")
		{
			// Match any port if rule.dst_port == -1, else match specific port
			if (rule.dst_port == -1 || rule.dst_port == ntohs(tcp_header->th_dport))
			{
				// If rule.content is empty, always match; else, look for content in payload
				if (rule.content.empty() || payload_str.find(rule.content) != std::string::npos)
				{
					std::cout << "[Alert] " << (rule.msg.empty() ? rule.content : rule.msg)
							  << " | src: " << source_ip << " : " << ntohs(tcp_header->th_sport)
							  << " dst: " << dest_ip << " : " << ntohs(tcp_header->th_dport) << std::endl;
				}
			}
		}
	}
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	PacketHandlerData data;

	// Default interface - can be overridden by command line argument
	const char *interface = "en0"; // Default for macOS
	if (argc > 1)
	{
		interface = argv[1];
	}

	rules = read_rules("rules.txt");
	if (rules.empty())
	{
		std::cerr << "Warning: No rules loaded. IDS will not detect any threats." << std::endl;
	}

	// Initialize Libnids
	if (!nids_init())
	{
		std::cerr << "nids_init() failed: " << nids_errbuf << std::endl;
		return 1;
	}

	// Set the device to listen on if provided as a command-line argument
	if (argc > 1)
	{
		nids_params.device = argv[1];
	}

	// Register the TCP callback function
	nids_register_tcp(tcp_callback);

	// Run the Libnids main loop
	std::cout << "Starting IDS and listening for network traffic..." << std::endl;
	nids_run();

	// nids_run() is a blocking call. This will only be reached on error.
	std::cerr << "nids_run() terminated: " << nids_errbuf << std::endl;

	return 0;
}
