#include "WebSocket.h"
#include "WebHelpers.h"
#include "bearssl.h"
#include <algorithm>
#include <xtl.h>

namespace web_socket {

	namespace internal {
		std::string base64_encode(const std::vector<uint8_t>& data) {
		    static const char* base64_chars =
		        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		        "abcdefghijklmnopqrstuvwxyz"
		        "0123456789+/";

		    std::string ret;
		    int i = 0;
		    int j = 0;
		    uint8_t char_array_3[3];
		    uint8_t char_array_4[4];

		    size_t in_len = data.size();
		    const uint8_t* bytes_to_encode = data.data();

		    while (in_len--) {
		        char_array_3[i++] = *(bytes_to_encode++);
		        if (i == 3) {
		            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		            char_array_4[3] = char_array_3[2] & 0x3f;

		            for(i = 0; (i < 4) ; i++)
		                ret += base64_chars[char_array_4[i]];
		            i = 0;
		        }
		    }

		    if (i) {
		        for(j = i; j < 3; j++)
		            char_array_3[j] = '\0';

		        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		        char_array_4[3] = char_array_3[2] & 0x3f;

		        for (j = 0; (j < i + 1); j++)
		            ret += base64_chars[char_array_4[j]];

		        while((i++ < 3))
		            ret += '=';
		    }
		    return ret;
		}

		// SHA-1 (using BearSSL)
		std::vector<uint8_t> sha1_hash(const std::string& input) {
		    br_sha1_context ctx;
		    br_sha1_init(&ctx);
		    br_sha1_update(&ctx, input.data(), input.length());
		    std::vector<uint8_t> hash(20); // SHA-1 produces 20 bytes
		    br_sha1_out(&ctx, hash.data());
		    return hash;
		}

		// Handshake
		std::string generate_websocket_key() {
			std::vector<uint8_t> keyBytes(16);
		    XeCryptRandom(keyBytes.data(), (DWORD)keyBytes.size());
		    return base64_encode(keyBytes);
		}

		std::string calculate_websocket_accept(const std::string& clientKey) {
		    std::string combined = clientKey + WEBSOCKET_GUID;
		    std::vector<uint8_t> sha1Hash = sha1_hash(combined);
		    return base64_encode(sha1Hash);
		}

		// Framing
		std::vector<uint8_t> generate_masking_key() {
		    std::vector<uint8_t> key(4);
		    XeCryptRandom(key.data(), (DWORD)key.size());

		    return key;
		}

		void unmask_payload(uint8_t* payload, size_t payloadLen, const uint8_t* maskingKey) {
		    for (size_t i = 0; i < payloadLen; ++i) {
		        payload[i] ^= maskingKey[i % 4];
		    }
		}

		int send_websocket_frame(XexUtils::Socket& socket, uint8_t opcode, const char* payload_data, size_t payloadLen) {
		    std::vector<uint8_t> frame;

		    // Header Byte 1: FIN (1 bit) | RSV1-3 (3 bits) | Opcode (4 bits)
		    uint8_t byte1 = 0x80 | (opcode & 0x0F); // FIN bit set (last fragment)

		    frame.push_back(byte1);

		    // Header Byte 2: Mask (1 bit) | Payload Length (7 bits, 16 bits, or 64 bits)
		    uint8_t byte2 = 0x80; // Mask bit MUST be set for client-to-server messages

		    if (payloadLen <= 125) {
		        byte2 |= static_cast<uint8_t>(payloadLen);
		        frame.push_back(byte2);
		    } else if (payloadLen <= 65535) { // 16-bit length
		        byte2 |= 126;
		        frame.push_back(byte2);
		        frame.push_back(static_cast<uint8_t>((payloadLen >> 8) & 0xFF));
		        frame.push_back(static_cast<uint8_t>(payloadLen & 0xFF));
		    } else { // 64-bit length
		        byte2 |= 127;
		        frame.push_back(byte2);
		        // Payload length in network byte order (big-endian)
		        for (int i = 7; i >= 0; --i) {
		            frame.push_back(static_cast<uint8_t>((payloadLen >> (i * 8)) & 0xFF));
		        }
		    }

		    // Masking Key (4 bytes)
		    std::vector<uint8_t> maskingKey = generate_masking_key();
		    frame.insert(frame.end(), maskingKey.begin(), maskingKey.end());

		    // Mask and add payload
		    if (payload_data && payloadLen > 0) {
		        std::vector<uint8_t> maskedPayload(payloadLen);
		        for (size_t i = 0; i < payloadLen; ++i) {
		            maskedPayload[i] = static_cast<uint8_t>(payload_data[i]) ^ maskingKey[i % 4];
		        }
		        frame.insert(frame.end(), maskedPayload.begin(), maskedPayload.end());
		    }

		    return socket.Send(reinterpret_cast<const char*>(frame.data()), frame.size());
		}

	} // internal

	HRESULT connect(XexUtils::Socket& socket, const std::string& host, const std::string& path, bool secure) {

		const unsigned char EC_DN[] = {
			0x30, 0x47, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
			0x02, 0x55, 0x53, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0A,
			0x13, 0x19, 0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x20, 0x54, 0x72, 0x75,
			0x73, 0x74, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20,
			0x4C, 0x4C, 0x43, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03,
			0x13, 0x0B, 0x47, 0x54, 0x53, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x52,
			0x34
		};

		const unsigned char EC_Q[] = {
			0x04, 0xF3, 0x74, 0x73, 0xA7, 0x68, 0x8B, 0x60, 0xAE, 0x43, 0xB8, 0x35,
			0xC5, 0x81, 0x30, 0x7B, 0x4B, 0x49, 0x9D, 0xFB, 0xC1, 0x61, 0xCE, 0xE6,
			0xDE, 0x46, 0xBD, 0x6B, 0xD5, 0x61, 0x18, 0x35, 0xAE, 0x40, 0xDD, 0x73,
			0xF7, 0x89, 0x91, 0x30, 0x5A, 0xEB, 0x3C, 0xEE, 0x85, 0x7C, 0xA2, 0x40,
			0x76, 0x3B, 0xA9, 0xC6, 0xB8, 0x47, 0xD8, 0x2A, 0xE7, 0x92, 0x91, 0x6A,
			0x73, 0xE9, 0xB1, 0x72, 0x39, 0x9F, 0x29, 0x9F, 0xA2, 0x98, 0xD3, 0x5F,
			0x5E, 0x58, 0x86, 0x65, 0x0F, 0xA1, 0x84, 0x65, 0x06, 0xD1, 0xDC, 0x8B,
			0xC9, 0xC7, 0x73, 0xC8, 0x8C, 0x6A, 0x2F, 0xE5, 0xC4, 0xAB, 0xD1, 0x1D,
			0x8A
		};

		const unsigned char RSA_DN[] = {
		    0x30, 0x31, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
		    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
		    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A,
		    0x13, 0x0A, 0x49, 0x53, 0x52, 0x47, 0x20, 0x2C,
		    0x49, 0x6E, 0x63, 0x2E, 0x31, 0x13, 0x30, 0x11,
		    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0A, 0x49,
		    0x53, 0x52, 0x47, 0x20, 0x52, 0x6F, 0x6F, 0x74,
		    0x20, 0x58, 0x31
		};
		const unsigned char RSA_N[] = {
		    0x00, 0xaf, 0x2f, 0x62, 0xe9, 0xf5, 0x3d, 0x1f, 0x64, 0x2e, 0x98, 0x0f, 0x09, 0x3a, 0x65, 0x9b,
		    0xf5, 0x77, 0x6f, 0x47, 0xdc, 0x96, 0xf9, 0x4e, 0x58, 0x91, 0x1f, 0x94, 0xb6, 0x1b, 0x7f, 0x7d,
		    0x25, 0xa4, 0x0c, 0xc2, 0x55, 0x43, 0xd6, 0x62, 0xe3, 0xf3, 0x82, 0xc5, 0x0b, 0x12, 0x4d, 0xb0,
		    0x0e, 0xb3, 0x4c, 0x4e, 0xf0, 0xac, 0x6a, 0x26, 0x4e, 0xd3, 0x93, 0xf4, 0x39, 0xd2, 0xc8, 0x2c,
		    0x3b, 0xc6, 0x0a, 0xc7, 0x57, 0x18, 0x6c, 0xd1, 0x60, 0x60, 0x87, 0xd8, 0xac, 0x00, 0x11, 0x5d,
		    0xb3, 0x69, 0x6a, 0x25, 0x80, 0xa5, 0x6f, 0x84, 0x2c, 0x1b, 0x33, 0x61, 0x4a, 0xe7, 0xd1, 0x8d,
		    0x1f, 0xa2, 0xb0, 0x0d, 0x2d, 0xea, 0xbb, 0x0e, 0x5f, 0xe2, 0x7f, 0xa5, 0x80, 0xd2, 0x5f, 0xb7,
		    0x25, 0x34, 0xb0, 0x4e, 0x76, 0x9e, 0x2c, 0x83, 0x25, 0xb2, 0x3e, 0x33, 0xe7, 0x2d, 0x5e, 0x45,
		    0x93, 0xa4, 0xb2, 0x2b, 0x73, 0x1a, 0x6c, 0xf4, 0x30, 0x95, 0x28, 0x3b, 0x6b, 0xa3, 0x75, 0x4d,
		    0x38, 0xbe, 0x7a, 0x11, 0x3c, 0xdf, 0x71, 0x33, 0x4f, 0x0e, 0x9e, 0x6d, 0xe5, 0xa6, 0x76, 0x7e,
		    0x3e, 0xf6, 0xf4, 0x91, 0x8a, 0xbe, 0x3d, 0xf4, 0x11, 0xc4, 0x91, 0x0a, 0xe3, 0x5c, 0x2f, 0xbe,
		    0x2e, 0x27, 0x3e, 0x61, 0x61, 0xb4, 0x12, 0xfa, 0xb9, 0xd4, 0x26, 0x44, 0xbd, 0x1a, 0xd3, 0x12,
		    0x68, 0x96, 0xa2, 0x92, 0x7a, 0x8b, 0x86, 0x4d, 0x12, 0x29, 0xa1, 0x77, 0x53, 0x4a, 0x9a, 0x35,
		    0xe2, 0xa1, 0x56, 0x45, 0xc5, 0xf3, 0xd7, 0x70, 0xd7, 0x91, 0x9f, 0x8c, 0x1b, 0xdf, 0x1c, 0x0b,
		    0xb1, 0x3d, 0xa7, 0xf2, 0xbb, 0xd9, 0x6b, 0x75, 0x8d, 0x2d, 0x7b, 0xc7, 0x19, 0x5b, 0x9f, 0x32,
		    0xbc, 0x3a, 0x1a, 0xd5, 0xa3, 0x93, 0xb3, 0xf9, 0x75, 0x26, 0x2e, 0x67, 0xf2, 0x77, 0x93, 0x41
		};
		const unsigned char RSA_E[] = { 0x01, 0x00, 0x01 };

	    if (secure) {
			//socket.InitContext();
	        HRESULT hr_anchor = socket.AddECTrustAnchor(EC_DN, sizeof(EC_DN), EC_Q, sizeof(EC_Q), XexUtils::Socket::Curve_secp384r1);
	        if (FAILED(hr_anchor)) {
	            XexUtils::Log::Print("Couldn't add elliptic curve trust anchor. HRESULT: 0x%08X", hr_anchor);
	            return E_FAIL;
	        }
			hr_anchor = socket.AddRsaTrustAnchor(RSA_DN, sizeof(RSA_DN), RSA_N, sizeof(RSA_N), RSA_E, sizeof(RSA_E));
			if (FAILED(hr_anchor)) {
	            XexUtils::Log::Print("Couldn't add RSA trust anchor. HRESULT: 0x%08X", hr_anchor);
	            return E_FAIL;
	        }
	    }

	    HRESULT hr_connect = socket.Connect();
	    if (FAILED(hr_connect)) {
	        XexUtils::Log::Print("Couldn't establish underlying TCP/TLS connection to %s. HRESULT: 0x%08X", host.c_str(), hr_connect);
	        return E_FAIL;
	    }
		
		// Handshake request
		// Mostly matches what was found in network analysis
		std::string clientKey = internal::generate_websocket_key();

	    std::string request = "GET " + path + " HTTP/1.1\r\n";
	    request += "Host: " + host + "\r\n";
	    request += "Pragma: no-cache\r\n";
	    request += "Cache-Control: no-cache\r\n";
	    request += "Upgrade: websocket\r\n";
	    request += "Sec-WebSocket-Version: 13\r\n";
	    request += "Accept-Language: en-GB\r\n";
	    request += "Sec-WebSocket-Key: " + clientKey + "\r\n";
	    request += "\r\n";


	    XexUtils::Log::Print("Sending handshake request to %s%s", host.c_str(), path.c_str());

	    if (socket.Send(request.c_str(), request.length()) == SOCKET_ERROR) {
	        XexUtils::Log::Print("Failed to send WebSocket handshake request.");
	        socket.Disconnect();
	        return E_FAIL;
	    }

	    std::string response_string;
	    char buffer[4096];
	    int bytesRead;
	    size_t headerEndPos = std::string::npos;
	    const int MAX_HANDSHAKE_READ_ATTEMPTS = 10;
	    int attempts = 0;

	    while (attempts < MAX_HANDSHAKE_READ_ATTEMPTS && (bytesRead = socket.Receive(buffer, sizeof(buffer))) > 0) {
	        response_string.append(buffer, bytesRead);
	        headerEndPos = response_string.find("\r\n\r\n");
	        if (headerEndPos != std::string::npos) {
	            break;
	        }
	        attempts++;
	    }

	    if (bytesRead == SOCKET_ERROR || headerEndPos == std::string::npos) {
	        XexUtils::Log::Print("Failed to receive or parse WebSocket handshake response. Bytes read: %d, Header end found: %s",
	                      bytesRead, (headerEndPos != std::string::npos ? "true" : "false"));
	        socket.Disconnect();
	        return E_FAIL;
	    }

	    std::string statusLine = response_string.substr(0, response_string.find("\r\n"));
	    if (statusLine.find("101 Switching Protocols") == std::string::npos) {
	        XexUtils::Log::Print("Server did not return 101 Switching Protocols: %s", statusLine.c_str());
	        socket.Disconnect();
	        return E_FAIL;
	    }

	    std::map<std::string, std::string> responseHeaders = web::get_headers(response_string);

	    std::string expectedAccept = internal::calculate_websocket_accept(clientKey);
	    auto it = responseHeaders.find("sec-websocket-accept");
	    if (it == responseHeaders.end() || it->second != expectedAccept) {
	        XexUtils::Log::Print("Sec-WebSocket-Accept header mismatch. Expected: '%s', Received: '%s'",
									expectedAccept.c_str(), (it != responseHeaders.end() ? it->second.c_str() : "N/A"));
	        socket.Disconnect();
	        return E_FAIL;
	    }

	    auto ext_it = responseHeaders.find("sec-websocket-extensions");
	    if (ext_it != responseHeaders.end())
	        XexUtils::Log::Print("Server negotiated extensions: %s", ext_it->second.c_str());
		else
	        XexUtils::Log::Print("Server did not negotiate extensions.");

	    XexUtils::Log::Print("WebSocket handshake successful!");

	    if (response_string.length() > headerEndPos + 4)
	        XexUtils::Log::Print("Initial data after handshake (might be first frame): %zu bytes", response_string.length() - (headerEndPos + 4));

	    return S_OK;
	}

	int send_text(XexUtils::Socket& socket, const std::string& message) {
	    return internal::send_websocket_frame(socket, internal::Text, message.c_str(), message.length());
	}

	int send_binary(XexUtils::Socket& socket, const std::vector<uint8_t>& data) {
	    return internal::send_websocket_frame(socket, internal::Binary, reinterpret_cast<const char*>(data.data()), data.size());
	}

	std::string receive_message(XexUtils::Socket& socket) {
	    std::string current_message_payload;
	    bool message_complete = false;

	    // Loop to read potentially fragmented frames until a complete message is formed
	    while (!message_complete) {
			internal::header header = { };
	        int bytes_read_total = 0;

	        // Read first two bytes (FIN/RSV/Opcode and Mask/PayloadLen)
	        int received = socket.Receive((char*)&header, 2);

	        if (received <= 0) {
				if (received == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT) {
			        XexUtils::Log::Print("Receive timed out, no data.");
			        return "";
			    }
	            XexUtils::Log::Print("Receive error or disconnect during header read (bytes 1-2).");
	            return "";
	        }
	        bytes_read_total += received;
			
	        size_t actual_payload_len = 0;
	        if (header.length <= 125) {
	            actual_payload_len = header.length;
	        } else if (header.length == 126) {
	            // Read next 2 bytes for 16-bit length
				char length[2];
	            received = socket.Receive(length, 2);
	            if (received <= 0) {
	                XexUtils::Log::Print("Receive error or disconnect during 16-bit length read.");
	                return "";
	            }
	            bytes_read_total += received;
	            actual_payload_len = (static_cast<size_t>(static_cast<unsigned char>(length[0])) << 8) | static_cast<unsigned char>(length[1]);
	        } else if (header.length == 127) {
	            // Read next 8 bytes for 64-bit length
				char length[8];
	            received = socket.Receive(length, 8);
	            if (received <= 0) {
	                XexUtils::Log::Print("Receive error or disconnect during 64-bit length read.");
	                return "";
	            }
	            bytes_read_total += received;
	            for (int i = 0; i < 8; ++i) {
	                actual_payload_len = (actual_payload_len << 8) | static_cast<unsigned char>(length[i]);
	            }
	        }

			XexUtils::Log::Print("actual_payload_len (unsigned): %u", actual_payload_len);
			
			if(actual_payload_len > 64 * 1024) {
	            XexUtils::Log::Print("Payload too big!", received);
				// Probably READY event
				// Consume rest of response
				char* discard_temp_buffer = (char*)malloc(4096);
	            size_t total_discarded = 0;
	            while (total_discarded < actual_payload_len) {
	                size_t bytes_to_read_this_chunk = actual_payload_len - total_discarded < 4096 ? actual_payload_len - total_discarded : 4096;

	                received = socket.Receive(discard_temp_buffer, bytes_to_read_this_chunk);
	                if (received <= 0) {
	                    XexUtils::Log::Print("Receive error or disconnect during payload discard read (Result: %d). This leaves data on socket buffer!).", received);
						free(discard_temp_buffer);
	                    return "";
	                }
	                total_discarded += received;
	            }
				free(discard_temp_buffer);
				std::cout << "Consumed" << std::endl;
				return "{\"event\": \"READY\"}";
			}

	        std::vector<uint8_t> frame_payload(actual_payload_len);
	        if (actual_payload_len > 0) {
	            int total_payload_received = 0;
	            while (total_payload_received < actual_payload_len) {
	                received = socket.Receive(reinterpret_cast<char*>(frame_payload.data() + total_payload_received), actual_payload_len - total_payload_received);
	                if (received <= 0) {
	                    XexUtils::Log::Print("Receive error or disconnect during payload read.");
	                    return "";
	                }
	                total_payload_received += received;
	            }
	        }

	        // Handle control frames
	        if (header.opcode == internal::Ping) {
	            XexUtils::Log::Print("Received PING frame. Responding with PONG.");
	            internal::send_websocket_frame(socket, internal::Pong, reinterpret_cast<const char*>(frame_payload.data()), frame_payload.size());
	            continue;
	        }

	    	if (header.opcode == internal::Pong) {
	            XexUtils::Log::Print("Received PONG frame.");
	        }
	    	else if (header.opcode == internal::Close) {
	            XexUtils::Log::Print("Received CLOSE frame.");
	            uint16_t closeCode = 1000;
	            std::string closeReason = "";
	            if (frame_payload.size() >= 2) {
	                closeCode = (static_cast<uint16_t>(frame_payload[0]) << 8) | frame_payload[1];
	                if (frame_payload.size() > 2) {
	                    closeReason = std::string(frame_payload.begin() + 2, frame_payload.end());
	                }
	            }
	            XexUtils::Log::Print("Close code: %u, Reason: %s", closeCode, closeReason.c_str());
	            return "";
	        }
			
	        // Handle data frames (Text or Binary)
	        if (header.opcode == internal::Text || header.opcode == internal::Binary || header.opcode == internal::Continuation) {
	            if (header.opcode != internal::Continuation) { // New message start (not a continuation frame)
	                current_message_payload.clear();
	            }
	            current_message_payload.append(reinterpret_cast<char*>(frame_payload.data()), frame_payload.size());

	            if (header.FIN) {
	                message_complete = true;
	                if (header.opcode == internal::Binary)
	                    XexUtils::Log::Print("Received binary WebSocket message (expected text).");
	            }
	        }
	    	else {
	            XexUtils::Log::Print("Received unsupported WebSocket opcode: %u", header.opcode);
	            internal::send_websocket_frame(socket, internal::Close, "\x03\xEA", 2);
	            return "";
	        }
	    }
	    return current_message_payload;
	}

	void disconnect(XexUtils::Socket& socket, uint16_t code, const std::string& reason) {
	    std::vector<uint8_t> payload;
	    payload.push_back(static_cast<uint8_t>((code >> 8) & 0xFF));
	    payload.push_back(static_cast<uint8_t>(code & 0xFF));
	    payload.insert(payload.end(), reason.begin(), reason.end());

	    XexUtils::Log::Print("Sending WebSocket close frame (code %u).", code);
	    internal::send_websocket_frame(socket, internal::Close, reinterpret_cast<const char*>(payload.data()), payload.size());

	    socket.Disconnect();
	    XexUtils::Log::Print("Underlying socket disconnected.");
	}

} // namespace web_socket