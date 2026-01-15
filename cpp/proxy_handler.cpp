#include "proxy_handler.h"
#include "settings.h"
#include "logger.h"
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <thread>
#include <netdb.h>
#include <regex>
#include <algorithm>

#define BUFFER_SIZE 65536

// Helper: Case insensitive replace
std::string replace_all(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return str;
}

// Helper: Regex replace
std::string regex_replace_str(std::string str, const std::string& pattern, const std::string& replacement) {
    try {
        std::regex re(pattern, std::regex_constants::icase);
        return std::regex_replace(str, re, replacement);
    } catch (...) {
        return str;
    }
}

// 1. MODIFY REQUEST
std::string modify_request(const std::string& data, const ProxyConfig& conf) {
    std::string modified = data;
    
    // Connection Close
    modified = regex_replace_str(modified, "Connection: keep-alive", "Connection: close");
    modified = regex_replace_str(modified, "Accept-Encoding:.*?\\r\\n", "");

    // User Agent Spoofing
    if (conf.spoof_user_agent && !conf.selected_user_agent.empty()) {
         modified = regex_replace_str(modified, "User-Agent:.*?\\r\\n", "User-Agent: " + conf.selected_user_agent + "\r\n");
    }

    // Strip Cookies
    if (conf.strip_cookies) {
        modified = regex_replace_str(modified, "Cookie:.*?\\r\\n", "");
    }
    
    return modified;
}

// 2. MODIFY RESPONSE
std::string modify_response(const std::string& data, const ProxyConfig& conf) {
    // Separate Header and Body
    size_t header_end = data.find("\r\n\r\n");
    if (header_end == std::string::npos) return data;

    std::string header = data.substr(0, header_end);
    std::string body = data.substr(header_end + 4);

    // Skip if not text/html to avoid corrupting binaries/images
    // BUT if block_images is on, we might check content-type
    bool is_html = (header.find("Content-Type: text/html") != std::string::npos);

    // Block Images implies simple rule: if it looks like an image request (hard to tell from response only efficiently without state, 
    // but we can check Content-Type)
    if (conf.block_images) {
        if (header.find("Content-Type: image") != std::string::npos) {
            // Replace with placeholder
            std::string new_body = "[IMAGE BLOCKED]";
            std::string new_header = header; // should fix content-length
            return new_header + "\r\n\r\n" + new_body; 
        }
        
        // Also strip <img> tags in HTML
        if (is_html) {
             body = regex_replace_str(body, "<img[^>]*>", "[IMG BLOCKED]");
        }
    }

    if (is_html) {
        // Rewrite HTTPS
        if (conf.rewrite_https) {
            body = replace_all(body, "href=\"http://", "href=\"https://");
        }

        // Censor Words
        if (conf.censor_enabled && !conf.censor_word_target.empty()) {
            body = regex_replace_str(body, conf.censor_word_target, conf.censor_word_replace);
        }

        // Inject Banner
        if (conf.inject_banner) {
            std::string banner = "<div style='background:red;color:white;text-align:center;padding:10px;font-weight:bold;position:fixed;top:0;left:0;width:100%;z-index:999999;'>!!! C++ PROXY ACTIV !!!</div><br><br><br>";
            if (body.find("<body") != std::string::npos) {
                body = regex_replace_str(body, "<body[^>]*>", "$&" + banner);
            } else {
                body = banner + body;
            }
        }
    }

    // Reconstruction
    std::string new_header = header;
    // Strip encodings
    new_header = regex_replace_str(new_header, "Transfer-Encoding:.*?\\r\\n", "");
    new_header = regex_replace_str(new_header, "Content-Encoding:.*?\\r\\n", "");
    new_header = regex_replace_str(new_header, "Connection:.*?\\r\\n", "Connection: close\r\n");
    
    // Update Length
    std::string new_len_str = "Content-Length: " + std::to_string(body.length());
    if (new_header.find("Content-Length:") != std::string::npos) {
        new_header = regex_replace_str(new_header, "Content-Length:\\s*\\d+", new_len_str);
    } else {
        new_header += "\r\n" + new_len_str;
    }

    return new_header + "\r\n\r\n" + body;
}

// Helper to get host/port
bool extract_host_port(const std::string& request, std::string& host, int& port) {
    std::regex host_regex("Host:\\s*([^\\r\\n]+)", std::regex_constants::icase);
    std::smatch match;
    if (std::regex_search(request, match, host_regex)) {
        std::string host_part = match[1].str();
        auto pos = host_part.find(':');
        if (pos != std::string::npos) {
            host = host_part.substr(0, pos);
            port = std::stoi(host_part.substr(pos + 1));
        } else {
            host = host_part;
            port = 80;
        }
        return true;
    }
    return false;
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    int bytes_read = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_read <= 0) {
        close(client_socket);
        return;
    }

    std::string request(buffer, bytes_read);
    
    // 1. Extract Host
    std::string host;
    int port;
    if (!extract_host_port(request, host, port)) {
        close(client_socket);
        return;
    }

    // Get current config
    ProxyConfig conf = SettingsManager::getInstance().getConfig();

    // CONNECT handling (Basic Tunneling for HTTPS - cannot modify content)
    if (request.substr(0, 7) == "CONNECT") {
        // ... (Simplified: Just fail or pass through blind? For now pass blind without decrypt)
        // Implementing full MITM SSL is complex (needs cert generation). 
        // For this task, we will just focus on HTTP modification as requested.
    }

    // Check blocked domains
    for (const auto& domain : conf.blocked_domains) {
        if (host.find(domain) != std::string::npos) {
            Logger::log("[BLOCK] Access denied to: " + host);
            std::string forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Length: 19\r\nConnection: close\r\n\r\n<h1>403 BLOCKED</h1>";
            send(client_socket, forbidden.c_str(), forbidden.length(), 0);
            close(client_socket);
            return;
        }
    }

    // 2. Modify Request
    std::string final_request_data = modify_request(request, conf);

    // Connect to Remote
    int remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) {
        Logger::log("[ERROR] Could not resolve host: " + host);
        close(client_socket);
        return;
    }

    struct sockaddr_in remote_addr;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(port);
    remote_addr.sin_addr = *((struct in_addr*)he->h_addr);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0) {
        Logger::log("[ERROR] Could not connect to: " + host);
        close(remote_socket);
        close(client_socket);
        return;
    }

    std::thread::id this_id = std::this_thread::get_id();
    // Simple hash for thread ID logging
    size_t id_hash = std::hash<std::thread::id>{}(this_id) % 1000;
    
    Logger::log("[T-" + std::to_string(id_hash) + "] [REQ] " + host);

    // Send modified request to remote
    send(remote_socket, final_request_data.c_str(), final_request_data.length(), 0);

    // Relay response back
    std::string response_buffer;
    while (true) {
        int n = recv(remote_socket, buffer, BUFFER_SIZE, 0);
        if (n <= 0) break;
        response_buffer.append(buffer, n);
    }
    
    // 3. Modify Response
    std::string final_response = modify_response(response_buffer, conf);
    
    send(client_socket, final_response.c_str(), final_response.length(), 0);
    
    if (response_buffer.length() != final_response.length()) {
         Logger::log("[FILTER] Content modified: " + std::to_string(response_buffer.length()) + " -> " + std::to_string(final_response.length()) + " bytes");
    }

    close(remote_socket);
    close(client_socket);
}
