#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <mutex>

#define LOG_PORT 8890

class Logger {
public:
    static void log(const std::string& message) {
        static int sock = -1;
        static struct sockaddr_in serverAddr;
        static std::mutex logMtx;

        std::lock_guard<std::mutex> lock(logMtx);

        if (sock == -1) {
            sock = socket(AF_INET, SOCK_DGRAM, 0);
            memset(&serverAddr, 0, sizeof(serverAddr));
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(LOG_PORT);
            serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        }

        std::string full_msg = message + "\n";
        sendto(sock, full_msg.c_str(), full_msg.length(), 0, (const struct sockaddr *)&serverAddr, sizeof(serverAddr));
        
        // Also print to stdout for debug
        // std::cout << message << std::endl;
    }
};

#endif
