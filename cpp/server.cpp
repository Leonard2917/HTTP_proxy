#include "server.h"
#include "proxy_handler.h"
#include "logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <vector>

Server::Server(int p) : port(p) {
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    if (listen(server_sock, 100) < 0) {
        perror("Listen failed");
        exit(1);
    }
}

void Server::start() {
    Logger::log("C++ Proxy Server Started on port " + std::to_string(port));
    
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);

        if (client_sock < 0) {
            continue;
        }

        //folosim pentru fiecare client cate un thread separat
        std::thread([client_sock](){
            handle_client(client_sock);
        }).detach();
    }
}
