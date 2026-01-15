#include "server.h"
#include "settings.h"
#include <iostream>
#include <thread>
#include <chrono>

// Future: Control Listener Thread for Settings updates from Python

int main(int argc, char* argv[]) {
    int port = 8888;
    if (argc > 1) {
        port = std::stoi(argv[1]);
    }

    // Force Settings Listener to start immediately
    SettingsManager::getInstance();

    Server server(port);
    server.start();

    return 0;
}
