#include "WebSocketClient.h"
#include "WebSocket.h"

namespace web_socket {

	web_socket_client::web_socket_client()
	    : socket_(), host_(""), path_(""), secure_(true),
	      connected_(false), stop_thread_(false), receive_thread_handle_(NULL),
	      on_connect_callback_(nullptr), on_disconnect_callback_(nullptr), on_error_callback_(nullptr)
	{
	    InitializeCriticalSection(&listeners_lock_);
	    InitializeCriticalSection(&socket_lock_);
	}

	web_socket_client::web_socket_client(const std::string& host, const std::string& path, bool secure)
	    : socket_(host, 443, secure), host_(host), path_(path), secure_(secure),
	      connected_(false), stop_thread_(false), receive_thread_handle_(NULL),
	      on_connect_callback_(nullptr), on_disconnect_callback_(nullptr), on_error_callback_(nullptr)
	{
	    InitializeCriticalSection(&listeners_lock_);
	    InitializeCriticalSection(&socket_lock_);
	}

	void web_socket_client::initialize(const std::string& host, const std::string& path, bool secure) {
	    if (connected_) {
	        XexUtils::Log::Print("Cannot initialize connected web_socket_client.");
	        return;
	    }
	    host_ = host;
	    path_ = path;
	    secure_ = secure;
	}

	web_socket_client::~web_socket_client() {
	    disconnect();
	    DeleteCriticalSection(&listeners_lock_);
	    DeleteCriticalSection(&socket_lock_);
	}

	bool web_socket_client::connect() {
	    if (connected_) {
	        XexUtils::Log::Print("Already connected.");
	        return true;
	    }
	    if (host_.empty()) {
	        XexUtils::Log::Print("Host or port not set. Call initialize() first or use appropriate constructor.");
	        return false;
	    }

	    XexUtils::Log::Print("Attempting to connect to WebSocket: %s%s", host_.c_str(), path_.c_str());

	    EnterCriticalSection(&socket_lock_);
	    bool success = (web_socket::connect(socket_, host_, path_, secure_) == S_OK);
	    LeaveCriticalSection(&socket_lock_);

	    if (success) {
	        connected_ = true;
	        XexUtils::Log::Print("WebSocket handshake successful! Starting receive thread.");

	        stop_thread_ = false;
	        receive_thread_handle_ = XexUtils::ThreadEx(receive_loop_thread_entry, this, EXCREATETHREAD_FLAG_SYSTEM, NULL);
	        if (receive_thread_handle_ == NULL) {
	            XexUtils::Log::Print("Failed to create receive thread.");
	            connected_ = false;
	            socket_.Disconnect();
	            return false;
	        }

	        if (on_connect_callback_) {
	            on_connect_callback_();
	        }
	        return true;
	    } else {
	        XexUtils::Log::Print("Failed to connect to WebSocket server.");
	        connected_ = false;
	        socket_.Disconnect();
	        return false;
	    }
	}

	void web_socket_client::disconnect() {
	    if (!connected_ && receive_thread_handle_ == NULL) {
	        XexUtils::Log::Print("Not connected or already disconnected.");
	        return;
	    }

	    XexUtils::Log::Print("Disconnecting WebSocket...");
	    stop_thread_ = true; 

	    if (receive_thread_handle_ != NULL) {
	        WaitForSingleObject(receive_thread_handle_, INFINITE);
	        CloseHandle(receive_thread_handle_);
	        receive_thread_handle_ = NULL;
	    }

	    EnterCriticalSection(&socket_lock_);
	    web_socket::disconnect(socket_);
	    LeaveCriticalSection(&socket_lock_);

	    connected_ = false;

	    if (on_disconnect_callback_) {
	        on_disconnect_callback_();
	    }
	    XexUtils::Log::Print("WebSocket disconnected.");
	}

	bool web_socket_client::send(const std::string& message) {
	    if (!connected_) {
	        XexUtils::Log::Print("Cannot send message: WebSocket not connected.");
	        return false;
	    }
	    EnterCriticalSection(&socket_lock_); // Protect socket.Send
	    int sent_bytes = web_socket::send_text(socket_, message);
	    LeaveCriticalSection(&socket_lock_);

	    if (sent_bytes == SOCKET_ERROR) {
	        XexUtils::Log::Print("Failed to send message over WebSocket.");
	        connected_ = false; // Assume disconnection on send error
	        return false;
	    }
	    return true;
	}

	void web_socket_client::on(message_condition condition, message_action action) {
	    EnterCriticalSection(&listeners_lock_);
		Listener l;
		l.condition = condition;
		l.action = action;
	    listeners_.push_back(l);
	    LeaveCriticalSection(&listeners_lock_);
	}

	void web_socket_client::on_message_contains(const std::string& substring, message_action action) {
	    message_condition condition = [substring](const std::string& message) {
	        return message.find(substring) != std::string::npos;
	    };
	    on(condition, action);
	}

	void web_socket_client::on_connect(connection_action action) {
	    on_connect_callback_ = action;
	}

	void web_socket_client::on_disconnect(connection_action action) {
	    on_disconnect_callback_ = action;
	}

	void web_socket_client::on_error(error_action action) {
	    on_error_callback_ = action;
	}

	DWORD WINAPI web_socket_client::receive_loop_thread_entry(LPVOID lpParam) {
	    web_socket_client* client = static_cast<web_socket_client*>(lpParam);
	    if (client) {
	        client->receive_loop();
	    }
	    return 0;
	}

	void web_socket_client::receive_loop() {
	    XexUtils::Log::Print("Receive thread started.");
	    while (connected_ && !stop_thread_) {

	        std::string received_message;
	        EnterCriticalSection(&socket_lock_);
	        received_message = web_socket::receive_message(socket_);
	        LeaveCriticalSection(&socket_lock_);

	        if (received_message.empty()) {
	            if (connected_) {
	                XexUtils::Log::Print("Receive thread: web_socket_client::receive_message returned empty but connection still marked as active. Assuming disconnect.");
	            }
	            connected_ = false;
	            break;
	        }

	        EnterCriticalSection(&listeners_lock_);
	        for (int i = 0; i < listeners_.size(); i++) {
	            if (listeners_.at(i).condition(received_message)) {
	                listeners_.at(i).action(received_message);
	            }
	        }
	        LeaveCriticalSection(&listeners_lock_);
	    }
	    XexUtils::Log::Print("Receive thread stopped.");
	}
} //web_socket