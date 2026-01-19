#pragma once
#include <map>
#include <string>

namespace web {
	std::map<std::string, std::string> get_headers(std::string response);
	std::string get_chunked_body(std::string response);
} //web