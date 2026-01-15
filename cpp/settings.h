#ifndef SETTINGS_H
#define SETTINGS_H

#include <string>
#include <mutex>
#include <map>
#include <vector>

struct ProxyConfig {
    bool spoof_user_agent = false;
    std::string selected_user_agent;
    bool strip_cookies = false;
    
    bool rewrite_https = false;
    bool censor_enabled = false;
    std::string censor_word_target;
    std::string censor_word_replace;
    bool block_images = false;
    bool inject_banner = true;
    std::vector<std::string> blocked_domains;
};

class SettingsManager {
public:
    static SettingsManager& getInstance() {
        static SettingsManager instance;
        return instance;
    }

    ProxyConfig getConfig() {
        std::lock_guard<std::mutex> lock(mtx);
        return config;
    }

    void updateConfig(const ProxyConfig& newConfig) {
        std::lock_guard<std::mutex> lock(mtx);
        config = newConfig;
    }

    void start_listener();

private:
    void parse_and_update(const std::string& json);
    SettingsManager() {
        start_listener();
    }
    std::mutex mtx;
    ProxyConfig config;
};

#endif
