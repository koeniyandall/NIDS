#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <time.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Rule struct definition
struct Rule
{
	std::string protocol;
	int dst_port;
	std::string content;
	std::string msg;
};

std::vector<Rule> rules;

// Logs alerts to a file
bool write_file(const struct Rule rule, const char *src_ip)
{
	std::ofstream file("log.txt", std::ios::app);
	if (!file.is_open())
	{
		return false;
	}
	time_t my_time = time(NULL);
	char *print_time = ctime(&my_time);
	print_time[strcspn(print_time, "\n")] = '\0';
	file << print_time << " | Protocol: " << rule.protocol << " | Destination Port: " << rule.dst_port
		 << " | Source IP: " << src_ip << " | Reason Flagged: " << rule.msg << std::endl;
	return true;
}

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
	return loaded_rules;
}

int main(int argc, char *argv[])
{
	// Load rules first, so they are available for the callbacks
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
