#ifndef JSON_HPP
#define JSON_HPP

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iostream>

// Minimal JSON parser for our specific use case (flat key-value pairs)
// We avoid external dependencies like nlohmann/json for this simple demo task.
class SimpleJson {
public:
    static std::map<std::string, std::string> parse(const std::string& json) {
        std::map<std::string, std::string> result;
        std::string clean = json;
        // Basic cleanup
        size_t start = clean.find('{');
        size_t end = clean.rfind('}');
        if (start == std::string::npos || end == std::string::npos) return result;
        
        clean = clean.substr(start + 1, end - start - 1);
        
        std::stringstream ss(clean);
        std::string segment;
        while(std::getline(ss, segment, ',')) {
            size_t colon = segment.find(':');
            if (colon != std::string::npos) {
                std::string key = trim_quotes(segment.substr(0, colon));
                std::string val = trim_quotes(segment.substr(colon + 1));
                result[key] = val;
            }
        }
        return result;
    }

private:
    static std::string trim_quotes(std::string s) {
        size_t first = s.find_first_not_of(" \t\n\r");
        if (std::string::npos == first) return s;
        size_t last = s.find_last_not_of(" \t\n\r");
        s = s.substr(first, (last - first + 1));
        
        if (s.length() >= 2 && s.front() == '"' && s.back() == '"') {
            return s.substr(1, s.length() - 2);
        }
        return s;
    }
};

#endif
