#include "Discord.h"
#include <json.h>

#include "RPC360.h"

bool g_discord_exiting = false;
bool g_discord_exited = false;

namespace discord {
	gateway_client::gateway_client(std::string token)
	    : web_socket_client_("gateway.discord.gg", "/?encoding=json&v=9", true),
	      token_(token),
	      heartbeat_interval_(0),
	      last_heartbeat_sent_time_(0),
	      last_sequence_number_(-1),
		  pending_rpc_payload_(""),
	      send_rpc_payload_(false),
		  ready_(false)
	{
	    InitializeCriticalSection(&this->client_lock_);
	    this->rpc_event_ = CreateEvent(NULL, FALSE, FALSE, NULL); // Manual reset, initially non-signaled

	    web_socket_client_.on_connect([this]() { this->handle_connect(); });
	    web_socket_client_.on_disconnect([this]() { this->handle_disconnect(); });
	    web_socket_client_.on_error([this](const std::string& msg) { this->handle_error(msg); });

	    web_socket_client_.on([](const std::string& message){ return true; }, // Condition: always true, process all messages
	                         [this](const std::string& message){ this->handle_gateway_message(message); });
	}

	gateway_client::~gateway_client() {
	    stop();
	    DeleteCriticalSection(&this->m_clientLock);
	    if (this->rpc_event_) {
	        CloseHandle(this->rpc_event_);
	        this->rpc_event_ = NULL;
	    }
	}

	DWORD WINAPI gateway_client::client_thread_entry_point(LPVOID lpParam) {
	    discord::gateway_client* client = static_cast<discord::gateway_client*>(lpParam);
	    if (client) {
	        client->client_loop();
	    }
	    return 0;
	}

	void gateway_client::start() {
	    g_discord_exited = false;
	    XexUtils::Log::Print("Starting gateway_client thread.");
	    loop_handle_ = XexUtils::ThreadEx(client_thread_entry_point, this, EXCREATETHREAD_FLAG_SYSTEM, NULL);
	    if (loop_handle_ == NULL) {
	        XexUtils::Log::Print("Failed to create gateway_client thread.");
	    }
	}

	void gateway_client::stop() {
	    if (loop_handle_ == NULL) {
	        XexUtils::Log::Print("Thread not running or already stopped.");
	        return;
	    }

	    XexUtils::Log::Print("Stopping gateway_client thread.");
	    g_discord_exiting = true;
	    
		web_socket_client_.disconnect();

	    WaitForSingleObject(loop_handle_, INFINITE);
	    CloseHandle(loop_handle_);
	    loop_handle_ = NULL;

	    XexUtils::Log::Print("Client thread stopped.");
	    g_discord_exited = true;
	}

	void gateway_client::handle_connect() {
	    XexUtils::Log::Print("WebSocket Client connected! (Callback received)");
	    heartbeat_interval_ = 5000;
	    last_heartbeat_sent_time_ = 0;
	    last_sequence_number_ = -1;
	    ready_ = false;
	}

	void gateway_client::handle_disconnect() {
	    XexUtils::Log::Print("WebSocket Client disconnected! (Callback received)");
	}

	void gateway_client::handle_error(const std::string& errorMessage) {
	    XexUtils::Log::Print("WebSocket Client Error: %s", errorMessage.c_str());
	}

	void gateway_client::handle_gateway_message(const std::string& message) {
	   // XexUtils::Log::Print("Received raw Gateway message: " + message);

	    Json::Value received_json;
	    Json::Reader reader;

	    if (reader.parse(message, received_json)) {
	        if (received_json.isObject() && received_json.isMember("op")) {
	            int opcode = received_json["op"].asInt();

	            if (received_json.isMember("s") && received_json["s"].isInt()) {
	                last_sequence_number_ = received_json["s"].asInt();
	                XexUtils::Log::Print("Updated sequence number (s): %d", last_sequence_number_);
	            }

	            switch (opcode) {
	                case 1: { // HEARTBEAT request
	                    send_heartbeat();
						last_heartbeat_sent_time_ = GetTickCount();
	                    break;
	                }
	                case 10: { // HELLO
	                    handle_hello(received_json);
	                    break;
	                }
	                case 11: { // HEARTBEAT_ACK
	                    handle_heartbeat_ack();
	                    break;
	                }
	                case 0: { // DISPATCH
	                    handle_dispatch(received_json);
	                    break;
	                }
	                case 7: { // RECONNECT
	                    handle_reconnect();
	                    break;
	                }
	                case 9: { // INVALID_SESSION
	                    handle_invalid_session();
	                    break;
	                }
	                default: {
	                    XexUtils::Log::Print("Received unknown opcode: %i", opcode);
	                    break;
	                }
	            }
	        } else {
	            XexUtils::Log::Print("Received WebSocket message is not a valid Gateway event (missing 'op' field).");
	        }
	    } else {
	        XexUtils::Log::Print("Failed to parse received Gateway message as JSON: %s", reader.getFormattedErrorMessages().c_str());
	    }
	}

	void gateway_client::handle_hello(const Json::Value& payload) {
	    XexUtils::Log::Print("Received HELLO opcode.");
	    if (payload.isMember("d") && payload["d"].isMember("heartbeat_interval")) {
	        heartbeat_interval_ = payload["d"]["heartbeat_interval"].asUInt();
	        XexUtils::Log::Print("Heartbeat interval: %u ms", heartbeat_interval_);

	        send_heartbeat();
	        last_heartbeat_sent_time_ = GetTickCount();

	        send_identify();

	    } else {
	        XexUtils::Log::Print("Malformed HELLO payload.");
	        web_socket_client_.disconnect();
	    }
	}

	void gateway_client::handle_dispatch(const Json::Value& payload) {
	    XexUtils::Log::Print("Received DISPATCH opcode.");
	    // Check for "READY" event
	    if (payload.isMember("t") && payload["t"].isString()) {
	        std::string event_type = payload["t"].asString();
	        if (event_type == "READY_SUPPLEMENTAL") {
	            XexUtils::Log::Print("Received READY_SUPPLEMENTAL event. Client is now fully online!");
				ready_ = true;
	        }
	    }
	}

	void gateway_client::handle_heartbeat_ack() {
	    XexUtils::Log::Print("Received HEARTBEAT_ACK.");
	}

	void gateway_client::handle_reconnect() {
	    XexUtils::Log::Print("Received RECONNECT opcode. Reconnecting.");
	    web_socket_client_.disconnect();
	}

	void gateway_client::handle_invalid_session() {
	    XexUtils::Log::Print("Received INVALID_SESSION opcode. Re-identifying.");
	    web_socket_client_.disconnect();
	}

	void gateway_client::send_heartbeat() {
	    Json::Value payload;
	    payload["op"] = 1;
	    if (last_sequence_number_ != -1) {
	        payload["d"] = (Json::Int)last_sequence_number_;
	    } else {
	        payload["d"] = Json::Value::null;
	    }

	    Json::FastWriter writer;
	    std::string payload_string = writer.write(payload);
	    
	    if (web_socket_client_.send(payload_string)) {
	        XexUtils::Log::Print("Heartbeat sent.");
	    } else {
	        XexUtils::Log::Print("Failed to send heartbeat.");
	    }
	}

	void gateway_client::send_identify() {
	    Json::Value payload;
	    payload["op"] = 2;

	    Json::Value d_payload;
	    d_payload["afk"] = false;
	    d_payload["capabilities"] = 1021;
	    d_payload["compress"] = false;
	    d_payload["token"] = token_;

	    d_payload["client_state"]["guild_hashes"] = Json::Value(Json::objectValue);
	    d_payload["client_state"]["highest_last_message_id"] = "0";
	    d_payload["client_state"]["private_channels_version"] = "0";
	    d_payload["client_state"]["read_state_version"] = 0;
	    d_payload["client_state"]["user_guild_settings_version"] = -1;
	    d_payload["client_state"]["user_settings_version"] = -1;

	    d_payload["presence"]["activities"] = Json::Value(Json::arrayValue);
	    d_payload["presence"]["afk"] = false;
	    d_payload["presence"]["since"] = 0;
	    d_payload["presence"]["status"] = "online";

	    d_payload["properties"]["os"] = "Windows 11";
	    d_payload["properties"]["browser"] = "Discord Client";
	    d_payload["properties"]["client_build_number"] = 152131;
	    d_payload["properties"]["client_event_source"] = Json::Value::null;
	    d_payload["properties"]["release_channel"] = "stable";
	    d_payload["properties"]["system_locale"] = "en-GB";

	    payload["d"] = d_payload;

	    Json::FastWriter writer;
	    std::string payload_string = writer.write(payload);

	    if (web_socket_client_.send(payload_string)) {
	        XexUtils::Log::Print("Identity sent.");
	    } else {
	        XexUtils::Log::Print("Failed to send identity.");
	    }
	}

	void gateway_client::send_rpc(
	    const std::string& game_name,
	    const std::string& image_uri,
	    uint32_t timestamp,
	    const std::string& console_custom
	) {
	    this->acquire_lock();
	    char gamertag_buffer[32];
		XUserGetName(0, gamertag_buffer, 32);

		Json::Value payload_json;
		payload_json["op"] = 3;

	    payload_json["d"]["since"] = 0;
	    payload_json["d"]["status"] = "online";
	    payload_json["d"]["afk"] = false;
		
	    payload_json["d"]["activities"][0]["application_id"] = "1395130912509006047";
	    payload_json["d"]["activities"][0]["name"] = game_name;
		payload_json["d"]["activities"][0]["details"] = gamertag_buffer;
	    payload_json["d"]["activities"][0]["state"] = console_custom;
	    payload_json["d"]["activities"][0]["type"] = 0;
	    payload_json["d"]["activities"][0]["platform"] = "xbox";
		
	    payload_json["d"]["activities"][0]["assets"]["large_image"] = "mp:" + image_uri;
	    payload_json["d"]["activities"][0]["assets"]["large_text"] = game_name;

	    Json::FastWriter writer;
	    pending_rpc_payload_ = writer.write(payload_json);
	    send_rpc_payload_ = true;
	    SetEvent(rpc_event_);
	    this->release_lock();
	}

	void gateway_client::acquire_lock() {
	    EnterCriticalSection(&this->client_lock_);
	}

	void gateway_client::release_lock() {
	    LeaveCriticalSection(&this->client_lock_);
	}


	void gateway_client::client_loop() {
	    XexUtils::Log::Print("Client loop thread started.");
	    while (!g_discord_exiting) {
	        if (!web_socket_client_.is_connected()) {
	            XexUtils::Log::Print("Attempting to connect...");
	            if (!web_socket_client_.connect()) {
	                XexUtils::Log::Print("Failed to connect. Retrying in 5 seconds...");
	                Sleep(5000);
	                continue;
	            }
	            XexUtils::Log::Print("Connected successfully.");
	        }

	        while (web_socket_client_.is_connected() && !g_discord_exiting) {
	            int poll_timeout_ms = heartbeat_interval_ > 0 ? (int)heartbeat_interval_ : 5000;

	            DWORD wait_result = WaitForSingleObject(rpc_event_, poll_timeout_ms);

	            if (wait_result == WAIT_OBJECT_0 && ready_) {
	                ResetEvent(rpc_event_);
	                this->acquire_lock();
	                if (send_rpc_payload_ && web_socket_client_.is_connected()) {
	                    XexUtils::Log::Print("\nSending pending RPC update: %s", pending_rpc_payload_.c_str());
	                    if (!web_socket_client_.send(pending_rpc_payload_)) {
	                        XexUtils::Log::Print("Failed to send pending RPC update.");
	                    }
	                } else if (!web_socket_client_.is_connected()) {
	                    XexUtils::Log::Print("WebSocket not open, cannot send pending RPC update (event signaled).");
	                }
	                send_rpc_payload_ = false;
	                this->release_lock();
	            } else if (wait_result == WAIT_FAILED) {
	                XexUtils::Log::Print("WaitForSingleObject error: %lu. Disconnecting.", GetLastError());
	                web_socket_client_.disconnect();
	                break;
	            }

	            long long current_time_ms = GetTickCount();
	            if (heartbeat_interval_ > 0 && (current_time_ms - last_heartbeat_sent_time_) >= heartbeat_interval_) {
	                send_heartbeat();
	                last_heartbeat_sent_time_ = current_time_ms;
	            }
	        }

	        if (!web_socket_client_.is_connected() || g_discord_exiting) {
	            if (!web_socket_client_.is_connected()) {
	            	ready_ = false;
	                XexUtils::Log::Print("Connection lost. Will attempt to reconnect.");
	                Sleep(5000);
	            }
	            if (g_discord_exiting) {
	                XexUtils::Log::Print("App exiting. Stopping.");
	                break;
	            }
	        }
	    }
	    g_discord_exited = true;
	    XexUtils::Log::Print("Client loop thread stopped.");
	}

	std::string gateway_client::proxy_image(const std::string& image_address) {

		auto socket = XexUtils::Socket("discord.com", 443, true);
		//socket.InitContext();

	    HRESULT hr_anchor = socket.AddECTrustAnchor(ec_dn, sizeof(ec_dn), ec_q, sizeof(ec_q), XexUtils::Socket::Curve_secp384r1);
	    if (FAILED(hr_anchor)) {
	        XexUtils::Log::Print("Couldn't add elliptic curve trust anchor. HRESULT: 0x%08X", hr_anchor);
	        return "";
	    }
		hr_anchor = socket.AddRsaTrustAnchor(rsa_dn, sizeof(rsa_dn), rsa_n, sizeof(rsa_n), rsa_e, sizeof(rsa_e));
		if (FAILED(hr_anchor)) {
		    XexUtils::Log::Print("Couldn't add RSA trust anchor. HRESULT: 0x%08X", hr_anchor);
		    return "";
		}

	    HRESULT hr_connect = socket.Connect();
	    if (FAILED(hr_connect)) {
	        XexUtils::Log::Print("Couldn't establish underlying TCP/TLS connection to %s. HRESULT: 0x%08X", "discord.com", hr_connect);
	        return "";
	    }

		Json::Value json;
		json["urls"][0] = image_address;
		std::string json_string = Json::FastWriter().write(json);

		std::stringstream request;
		request << "POST /api/v9/applications/1395130912509006047/external-assets HTTP/1.1\r\n";
		request << "Host: discord.com\r\n";
		request << "Authorization: " << g_token.c_str() << "\r\n";
		request << "Connection: close\r\n";
		request << "Content-Type: application/json\r\n";
		request << "Content-Length: " << (int)json_string.length() << "\r\n";
		request << "\r\n";
		request << json_string;
		request << "\r\n";

		auto request_string = request.str();

		auto sent_bytes = socket.Send(request_string.c_str(), request_string.length());
	    if (sent_bytes != request_string.length()) {	
	        XexUtils::Log::Print("Not all packets were sent");
	        socket.Disconnect();
			return "";
	    }

	    std::string response_buffer;
	    char buffer[1024];
		memset(buffer, '\0', sizeof(buffer));
	    int r = 0;
	    while ((r = socket.Receive(buffer, sizeof(buffer) - 1)) > 0) {
	       buffer[r] = '\0';
	       response_buffer.append(buffer, r);
		   memset(buffer, '\0', sizeof(buffer));
	    }

		std::string headers = std::string(response_buffer).substr(0, std::string(response_buffer).find("\r\n\r\n"));
		std::string body = std::string(response_buffer).substr(std::string(response_buffer).find("\r\n\r\n") + 4);
		
		size_t transfer_encoding_pos = headers.find("Transfer-Encoding: chunked");
	    std::string json_payload_str;

	    if (transfer_encoding_pos != std::string::npos) {        
	        std::stringstream chunk_parser_stream(body);
	        std::string line;
	        size_t total_json_bytes_read = 0;

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
	                return "";
	            }
	            
	            json_payload_str.append(chunk_data.data(), chunk_len);

	            if (chunk_parser_stream.peek() == '\r') {
	                chunk_parser_stream.ignore();
	                if (chunk_parser_stream.peek() == '\n') chunk_parser_stream.ignore();
	            } else {
	                 XexUtils::Log::Print("Missing CRLF after chunk data.");
	            }

	            total_json_bytes_read += chunk_len;
	        }
	    } else {
	        json_payload_str = body;
	    }
		socket.Disconnect();

		Json::Value response;
		Json::Reader reader;
		if(!reader.parse(json_payload_str, response)) {
			std::cout << reader.getFormattedErrorMessages() << std::endl;
			return "";
		}

		return response[0]["external_asset_path"].asString();
	}

} // namespace discord