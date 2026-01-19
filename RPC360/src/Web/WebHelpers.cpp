#include "WebHelpers.h"
#include "XexUtils.h"

#include <algorithm>
#include <sstream>

namespace web {
	std::map<std::string, std::string> get_headers(std::string response) {
		std::string headers_string = response.substr(0, response.find("\r\n\r\n"));

		std::map<std::string, std::string> headers;
		size_t current_position = 0;

		while (current_position < headers_string.npos) {
	        size_t line_end = headers_string.find("\r\n", current_position);
	        if (line_end == std::string::npos) break;

	        std::string line = headers_string.substr(current_position, line_end - current_position);
	        size_t colonPos = line.find(":");
	        if (colonPos != std::string::npos) {
	            std::string key = line.substr(0, colonPos);
	            std::string value = line.substr(colonPos + 1);

	            key.erase(0, key.find_first_not_of(" \t"));
	            key.erase(key.find_last_not_of(" \t") + 1);
	            value.erase(0, value.find_first_not_of(" \t"));
	            value.erase(value.find_last_not_of(" \t") + 1);

	            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
	            headers[key] = value;
	        }
	        current_position = line_end + 2;
	    }

		return headers;
	}

	std::string get_chunked_body(std::string response) {
		std::string headers = response.substr(0, response.find("\r\n\r\n"));
		std::string body = response.substr(response.find("\r\n\r\n") + 4);

		size_t transfer_encoding_pos = headers.find("Transfer-Encoding: chunked");
	    std::string result;

	    if (transfer_encoding_pos != std::string::npos) {        
	        std::stringstream chunk_parser_stream(body);
	        std::string line;
	        size_t total_body_bytes_read = 0;

	        while (std::getline(chunk_parser_stream, line, '\r')) {
	            if (chunk_parser_stream.peek() == '\n') {
	                chunk_parser_stream.ignore();
	            }
        		else
	                 XexUtils::Log::Print("Missing LF after CR in chunked body line.");
				
	            std::stringstream hex_ss;
	            hex_ss << std::hex << line;
	            size_t chunk_len = 0;
	            hex_ss >> chunk_len;

	            if (chunk_len == 0)
	                break;

	            std::string chunk_data;
				chunk_data.resize(chunk_len);
	            chunk_parser_stream.read((char*)chunk_data.data(), chunk_len);

	            if (!chunk_parser_stream) {
	                XexUtils::Log::Print("Error reading chunk data from stream.");
	                break;
	            }
	            
	            result.append(chunk_data.data(), chunk_len);

	            if (chunk_parser_stream.peek() == '\r') {
	                chunk_parser_stream.ignore();
	                if (chunk_parser_stream.peek() == '\n') chunk_parser_stream.ignore();
	            } else {
	                 XexUtils::Log::Print("Missing CRLF after chunk data.");
	            }

	            total_body_bytes_read += chunk_len;
	        }
	    } else {
	        result = body;
	    }

		return result;
	}
} //web