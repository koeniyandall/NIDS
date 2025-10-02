#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <nids.h>

// Struct to define a detection rule
struct Rule
{
	std::string protocol; // e.g., "tcp"
	int dst_port;		  // -1 means any
	std::string content;  // keyword to search for in payload
	std::string msg;	  // alert message
};

std::vector<Rule> rules; // Global rule list

// Function to load rules from a file
std::vector<Rule> read_rules(const std::string &filename)
{
	std::vector<Rule> loaded_rules;
	std::ifstream file(filename);
	if (!file.is_open())
	{
		std::cerr << "Error: Could not open rules file '" << filename << "'\n";
		return loaded_rules;
	}

	std::string line;
	while (std::getline(file, line))
	{
		if (line.empty() || line[0] == '#')
			continue;

		Rule rule;
		std::istringstream iss(line);
		std::string action, proto, src, src_port, arrow, dst, dst_port;

		// Very simple parsing (e.g., alert tcp any any -> any 80 (msg:"X"; content:"Y";))
		iss >> action >> rule.protocol >> src >> src_port >> arrow >> dst >> dst_port;

		// Convert dst_port
		rule.dst_port = (dst_port == "any") ? -1 : std::stoi(dst_port);

		// Parse options inside ()
		size_t start = line.find('(');
		size_t end = line.find(')');
		if (start != std::string::npos && end != std::string::npos)
		{
			std::string options = line.substr(start + 1, end - start - 1);

			size_t msg_pos = options.find("msg:\"");
			if (msg_pos != std::string::npos)
			{
				size_t begin = msg_pos + 5;
				size_t end_quote = options.find("\"", begin);
				rule.msg = options.substr(begin, end_quote - begin);
			}

			size_t content_pos = options.find("content:\"");
			if (content_pos != std::string::npos)
			{
				size_t begin = content_pos + 9;
				size_t end_quote = options.find("\"", begin);
				rule.content = options.substr(begin, end_quote - begin);
			}
		}

		loaded_rules.push_back(rule);
	}

	std::cout << "Loaded " << loaded_rules.size() << " rules.\n";
	return loaded_rules;
}

// TCP callback function for libnids
void tcp_callback(struct tcp_stream *ts, void **param)
{
	if (ts->nids_state == NIDS_CLOSE || ts->nids_state == NIDS_RESET || ts->nids_state == NIDS_TIMED_OUT)
		return;

	if (ts->nids_state == NIDS_DATA)
	{
		const char *payload;
		int payload_len;

		if (ts->client.count_new > 0)
		{
			payload = ts->client.data;
			payload_len = ts->client.count_new;
		}
		else if (ts->server.count_new > 0)
		{
			payload = ts->server.data;
			payload_len = ts->server.count_new;
		}
		else
		{
			return;
		}

		std::string payload_str(payload, payload_len);

		char src_ip[INET_ADDRSTRLEN];
		char dst_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ts->addr.saddr, src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ts->addr.daddr, dst_ip, INET_ADDRSTRLEN);
		uint16_t src_port = ntohs(ts->addr.source);
		uint16_t dst_port = ntohs(ts->addr.dest);

		for (const auto &rule : rules)
		{
			if (rule.protocol != "tcp")
				continue;

			if (rule.dst_port != -1 && rule.dst_port != dst_port)
				continue;

			if (!rule.content.empty() && payload_str.find(rule.content) == std::string::npos)
				continue;

			std::cout << "[Alert] " << (rule.msg.empty() ? rule.content : rule.msg)
					  << " | src: " << src_ip << ":" << src_port
					  << " -> dst: " << dst_ip << ":" << dst_port << "\n";
		}
	}
}

int main(int argc, char *argv[])
{
	// Set interface (default: eth0)
	if (argc > 1)
		nids_params.device = argv[1];
	else
		nids_params.device = "en0"; // or "en0" for macOS

	// Optional: capture entire packet
	nids_params.scan_num_hosts = 0;

	// Load rules
	rules = read_rules("rules.txt");
	if (rules.empty())
	{
		std::cerr << "Warning: No rules loaded.\n";
	}

	// Initialize NIDS
	if (!nids_init())
	{
		std::cerr << "nids_init() failed: " << nids_errbuf << "\n";
		return 1;
	}

	// Register callback
	nids_register_tcp(tcp_callback);

	std::cout << "Starting IDS on interface '" << nids_params.device << "'...\n";
	nids_run();

	return 0;
}
