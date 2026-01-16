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

//inlocuieste toate aparitiile unui substring in alt string
std::string replace_all(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return str;
}

//aplica un replace pe baza de regex, fara diferentiere intre majuscule si minuscule
std::string regex_replace_str(std::string str, const std::string& pattern, const std::string& replacement) {
    try {
        std::regex re(pattern, std::regex_constants::icase);
        return std::regex_replace(str, re, replacement);
    } catch (...) {
        return str;
    }
}

//modifica cererile http inainte de a fi trimise catre serverul destinatie
std::string modify_request(const std::string& data, const ProxyConfig& conf) {
    std::string modified = data;

    //forteaza inchiderea conexiunii pentru a simplifica citirea raspunsului
    modified = regex_replace_str(modified, "Connection: keep-alive", "Connection: close");

    //elimina compresia pentru a permite inspectia textului clar
    modified = regex_replace_str(modified, "Accept-Encoding:.*?\\r\\n", "");

    //inlocuieste user-agent-ul daca optiunea este activata
    if (conf.spoof_user_agent && !conf.selected_user_agent.empty()) {
         modified = regex_replace_str(modified, "User-Agent:.*?\\r\\n", "User-Agent: " + conf.selected_user_agent + "\r\n");
    }

    //elimina cookie-urile pentru a preveni urmarirea sesiunilor
    if (conf.strip_cookies) 
    {
        //modified = regex_replace_str(modified, "Cookie:.*?\\r\\n", "");if (modified.find("Cookie:") != std::string::npos) {
        Logger::log("[filter] am eliminat cookie-urile din cerere");
        modified = regex_replace_str(modified, "Cookie:.*?\\r\\n", "");
    }

    return modified;
}

//gestioneaza o conexiune individuala venita de la browser
void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];

    //seteaza un timeout scurt pentru handshake-ul initial
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

    //extrage host-ul si portul din cerere
    std::string host;
    int port;
    if (!extract_host_port(request, host, port)) {
        close(client_socket);
        return;
    }

    //incarca setarile curente din managerul global
    ProxyConfig conf = SettingsManager::getInstance().getConfig();

    //verifica daca domeniul este blocat
    for (const auto& domain : conf.blocked_domains) {
        if (host.find(domain) != std::string::npos) {
            Logger::log("[block] acces interzis catre: " + host);
            std::string forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Length: 19\r\nConnection: close\r\n\r\n<h1>403 BLOCKED</h1>";
            send(client_socket, forbidden.c_str(), forbidden.length(), 0);
            close(client_socket);
            return;
        }
    }

    //trateaza conexiunile https prin realizarea unui tunel tcp(doar transmite mai departe, nu face modificari)
    if (request.substr(0, 7) == "CONNECT") {
        Logger::log("[https] tunel catre " + host + ":" + std::to_string(port));

        int remote_socket = socket(AF_INET, SOCK_STREAM, 0);
        struct hostent* he = gethostbyname(host.c_str());
        if (!he) {
            close(client_socket);
            return;
        }

        struct sockaddr_in remote_addr;
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(port);
        remote_addr.sin_addr = *((struct in_addr*)he->h_addr);

        if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0) {
            close(remote_socket);
            close(client_socket);
            return;
        }

        //confirma browserului ca tunelul este deschis
        std::string ok_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(client_socket, ok_msg.c_str(), ok_msg.length(), 0);

        //elimina timeout-ul pentru sesiuni https de lunga durata
        struct timeval zero_tv = {0, 0};
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&zero_tv, sizeof zero_tv);

        //porneste redirectionarea bidirectionala a datelor
        handle_tunnel(client_socket, remote_socket);

        close(remote_socket);
        close(client_socket);
        return;
    }

    //aplica filtrele pe cererea http
    std::string final_request_data = modify_request(request, conf);

    //creeaza conexiunea catre serverul destinatie
    int remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) {
        Logger::log("[error] nu s-a putut rezolva host-ul: " + host);
        close(client_socket);
        return;
    }

    struct sockaddr_in remote_addr;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(port);
    remote_addr.sin_addr = *((struct in_addr*)he->h_addr);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0) {
        Logger::log("[error] nu s-a putut realiza conexiunea cu: " + host);
        close(remote_socket);
        close(client_socket);
        return;
    }

    //logheaza cererea impreuna cu id-ul thread-ului
    std::thread::id this_id = std::this_thread::get_id();
    size_t id_hash = std::hash<std::thread::id>{}(this_id) % 1000;
    Logger::log("[t-" + std::to_string(id_hash) + "] [req] " + host);

    //trimite cererea modificata catre server
    send(remote_socket, final_request_data.c_str(), final_request_data.length(), 0);

    //receptioneaza complet raspunsul de la server
    std::string response_buffer;
    while (true) {
        int n = recv(remote_socket, buffer, BUFFER_SIZE, 0);
        if (n <= 0) break;
        response_buffer.append(buffer, n);
    }

    //aplica filtrele si modificarile asupra raspunsului
    std::string final_response = modify_response(response_buffer, conf);

    //trimite raspunsul procesat catre browser
    send(client_socket, final_response.c_str(), final_response.length(), 0);

    if (response_buffer.length() != final_response.length()) {
         Logger::log("[filter] continut modificat: " + std::to_string(response_buffer.length()) + " -> " + std::to_string(final_response.length()) + " bytes");
    }

    close(remote_socket);
    close(client_socket);
}

//modifica raspunsurile serverului inainte de a fi trimise catre client
//(se aplica modificarile selectate din interfata grafica)
std::string modify_response(const std::string& data, const ProxyConfig& conf) {
    size_t header_end = data.find("\r\n\r\n");
    if (header_end == std::string::npos) return data;

    std::string header = data.substr(0, header_end);
    std::string body = data.substr(header_end + 4);

    bool is_html = (header.find("Content-Type: text/html") != std::string::npos);

    //blocheaza imaginile sau elimina tag-urile img din html
    if (conf.block_images) {
        if (header.find("Content-Type: image") != std::string::npos) {
            std::string new_body = "[image blocked]";
            return header + "\r\n\r\n" + new_body;
        }

        if (is_html) {
             body = regex_replace_str(body, "<img[^>]*>", "[img blocked]");
        }
    }

    if (is_html) {
        //rescrie link-urile daca optiunea este activa
        if (conf.rewrite_https) {
            body = replace_all(body, "href=\"http://", "href=\"https://");
        }

        //aplica cenzura folosind expresii regulate
        if (conf.censor_enabled && !conf.censor_word_target.empty()) {
            body = regex_replace_str(body, conf.censor_word_target, conf.censor_word_replace);
        }

        //injecteaza un banner vizibil in pagina html
        if (conf.inject_banner) {
            std::string banner = "<div style='background:red;color:white;text-align:center;padding:10px;font-weight:bold;position:fixed;top:0;left:0;width:100%;z-index:999999;'>!!! c++ proxy activ !!!</div><br><br><br>";
            if (body.find("<body") != std::string::npos) {
                body = regex_replace_str(body, "<body[^>]*>", "$&" + banner);
            } else {
                body = banner + body;
            }
        }
    }

    //elimina headerele incompatibile si recalculeaza content-length
    std::string new_header = header;
    new_header = regex_replace_str(new_header, "Transfer-Encoding:.*?\\r\\n", "");
    new_header = regex_replace_str(new_header, "Content-Encoding:.*?\\r\\n", "");
    new_header = regex_replace_str(new_header, "Connection:.*?\\r\\n", "Connection: close\r\n");

    std::string new_len_str = "Content-Length: " + std::to_string(body.length());
    if (new_header.find("Content-Length:") != std::string::npos) {
        new_header = regex_replace_str(new_header, "Content-Length:\\s*\\d+", new_len_str);
    } else {
        new_header += "\r\n" + new_len_str;
    }

    return new_header + "\r\n\r\n" + body;
}

//extrage host-ul si portul din cererile http si https
bool extract_host_port(const std::string& request, std::string& host, int& port) {
    if (request.substr(0, 8) == "CONNECT ") {
        size_t first_space = 7;
        size_t second_space = request.find(' ', first_space + 1);
        if (second_space != std::string::npos) {
            std::string uri = request.substr(first_space + 1, second_space - first_space - 1);
            auto pos = uri.find(':');
            if (pos != std::string::npos) {
                host = uri.substr(0, pos);
                try {
                    port = std::stoi(uri.substr(pos + 1));
                    return true;
                } catch(...) {}
            }
        }
    }

    std::regex host_regex("Host:\\s*([^\\r\\n]+)", std::regex_constants::icase);
    std::smatch match;
    if (std::regex_search(request, match, host_regex)) {
        std::string host_part = match[1].str();
        auto pos = host_part.find(':');
        if (pos != std::string::npos) {
            host = host_part.substr(0, pos);
            try {
                port = std::stoi(host_part.substr(pos + 1));
            } catch(...) { port = 80; }
        } else {
            host = host_part;
            port = 80;
        }
        return true;
    }
    return false;
}

//redirectioneaza datele brute intre client si server folosind select()
void handle_tunnel(int client_sock, int remote_sock) {
    fd_set read_fds;
    int max_fd = (client_sock > remote_sock) ? client_sock : remote_sock;
    char buffer[8192];

    while (true) {
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        FD_SET(remote_sock, &read_fds);

        struct timeval timeout;
        timeout.tv_sec = 300;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity <= 0) break;

        if (FD_ISSET(client_sock, &read_fds)) {
            int n = recv(client_sock, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            send(remote_sock, buffer, n, 0);
        }

        if (FD_ISSET(remote_sock, &read_fds)) {
            int n = recv(remote_sock, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            send(client_sock, buffer, n, 0);
        }
    }
}
