#include "settings.h"
#include "json_utils.h"
#include "logger.h"
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>

#define CONTROL_PORT 8889

void SettingsManager::start_listener() {
    std::thread([this]() {
        int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (serv_sock < 0) return;

        int opt = 1;
        setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(CONTROL_PORT);

        if (bind(serv_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) return;
        listen(serv_sock, 5);

        Logger::log("[SYSTEM] Settings Listener active on port " + std::to_string(CONTROL_PORT));

        while (true) {
            int client = accept(serv_sock, NULL, NULL);
            if (client >= 0) {
                char buffer[4096];
                int n = recv(client, buffer, sizeof(buffer) - 1, 0);
                if (n > 0) {
                    buffer[n] = '\0';
                    std::string payload(buffer);
                    parse_and_update(payload);
                }
                close(client);
            }
        }
    }).detach();
}

void SettingsManager::parse_and_update(const std::string& json) {
    auto map = SimpleJson::parse(json);
    
    std::lock_guard<std::mutex> lock(mtx);
    if(map.count("spoof_user_agent")) config.spoof_user_agent = (map["spoof_user_agent"] == "true");
    if(map.count("selected_user_agent")) config.selected_user_agent = map["selected_user_agent"];
    if(map.count("strip_cookies")) config.strip_cookies = (map["strip_cookies"] == "true");
    if(map.count("rewrite_https")) config.rewrite_https = (map["rewrite_https"] == "true");
    if(map.count("censor_enabled")) config.censor_enabled = (map["censor_enabled"] == "true");
    if(map.count("censor_word_target")) config.censor_word_target = map["censor_word_target"];
    if(map.count("censor_word_replace")) config.censor_word_replace = map["censor_word_replace"];
    if(map.count("block_images")) config.block_images = (map["block_images"] == "true");
    if(map.count("inject_banner")) config.inject_banner = (map["inject_banner"] == "true");
    
    if (map.count("blocked_domains")) {
        config.blocked_domains.clear();
        std::string raw = map["blocked_domains"];
        std::stringstream ss(raw);
        std::string segment;
        while(std::getline(ss, segment, '|')) {
            // Trim spaces
            size_t first = segment.find_first_not_of(' ');
            if (std::string::npos != first) {
                 size_t last = segment.find_last_not_of(' ');
                 config.blocked_domains.push_back(segment.substr(first, (last - first + 1)));
            }
        }
    }
    
    std::string domain_log = "[CONFIG] Blocked Domains (" + std::to_string(config.blocked_domains.size()) + "): ";
    for(const auto& d : config.blocked_domains) domain_log += "[" + d + "] ";
    Logger::log(domain_log);

    Logger::log("[CONFIG] Settings updated from GUI.");
}
