#ifndef WEBSOCKETCLIENT_H
#define WEBSOCKETCLIENT_H

#include "XexUtils.h"

#include <string>
#include <vector>
#include <functional>
#include <xtl.h>

namespace web_socket {
	class web_socket_client
	{
	public:
	    typedef std::function<bool(const std::string& message)> message_condition;
	    typedef std::function<void(const std::string& message)> message_action;
	    typedef std::function<void(const std::string& error_message)> error_action;
	    typedef std::function<void()> connection_action;

	    web_socket_client();
	    web_socket_client(const std::string& host, const std::string& path, bool secure = true);
	    ~web_socket_client();

	    void initialize(const std::string& host, const std::string& path, bool secure = true);
	    bool connect();
	    bool send(const std::string& message);

	    void on(message_condition condition, message_action action);
	    void on_message_contains(const std::string& substring, message_action action);
	    void on_connect(connection_action action);
	    void on_disconnect(connection_action action);
	    void on_error(error_action action);

	    void disconnect();

	    bool is_connected() const { return connected_; }

	private:
	    CRITICAL_SECTION socket_lock_; 
	    XexUtils::Socket socket_;
	    std::string host_;
	    std::string path_;
	    bool secure_;
	    bool connected_;
	    bool stop_thread_;

	    struct Listener {
	        message_condition condition;
	        message_action action;
	    };
	    std::vector<Listener> listeners_;
	    CRITICAL_SECTION listeners_lock_;

	    connection_action on_connect_callback_;
	    connection_action on_disconnect_callback_;
	    error_action on_error_callback_;

	    HANDLE receive_thread_handle_;

	    void receive_loop();
	    static DWORD WINAPI receive_loop_thread_entry(LPVOID lpParam);
	};
} // web_socket
#endif