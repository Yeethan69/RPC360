#ifndef XEX_WEBSOCKET_H
#define XEX_WEBSOCKET_H

#include "XexUtils.h"
#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace web_socket
{
	HRESULT connect(XexUtils::Socket& socket, const std::string& host, const std::string& path, bool secure = true);
	int send_text(XexUtils::Socket& socket, const std::string& message);
	int send_binary(XexUtils::Socket& socket, const std::vector<uint8_t>& data);
	std::string receive_message(XexUtils::Socket& socket);
	void disconnect(XexUtils::Socket& socket, uint16_t code = 1000, const std::string& reason = "");

	namespace internal
	{
	    enum Opcode
	    {
	        Continuation = 0x0,
	        Text = 0x1,
	        Binary = 0x2,
	        Close = 0x8,
	        Ping = 0x9,
	        Pong = 0xA
	    };

		struct header {
			byte FIN : 1;
			byte RSV1 : 1;
			byte RSV2 : 1;
			byte RSV3 : 1;
			byte opcode : 4;
			uint8_t MASK : 1;
			uint8_t length : 7;
		};

	    std::string base64_encode(const std::vector<uint8_t>& data);
	    std::vector<uint8_t> sha1_hash(const std::string& input);
	    std::string generate_websocket_key();
	    std::string calculate_websocket_accept(const std::string& clientKey);
	    std::vector<uint8_t> generate_masking_key();
	    void unmask_payload(uint8_t* payload, size_t payloadLen, const uint8_t* maskingKey);
	    int send_websocket_frame(XexUtils::Socket& socket, uint8_t opcode, const char* payload_data, size_t payloadLen);

	    static const std::string WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	}// internal

} // web_socket

#endif // XEX_WEBSOCKET_H