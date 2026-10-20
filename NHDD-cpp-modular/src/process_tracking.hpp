// Package matching and generation-pinned descendant tracking.
#pragma once
#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

struct TrackedProcess {
    int pid = 0;
    int parent = 0;
    uint64_t starttime = 0;
    std::string command;
};

class PackageProcessTracker {
public:
    static bool valid_package(const std::string& value) {
        if (value.empty() || value.size() > 255 || value.front() == '.' ||
            value.back() == '.') return false;
        bool dot = false;
        for (unsigned char c : value) {
            if (c == '.') { dot = true; continue; }
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_')) return false;
        }
        return dot && value.find("..") == std::string::npos;
    }
    static bool matches(const std::string& package, const std::string& command) {
        return command == package ||
            (command.size() > package.size() + 1 &&
             command.compare(0, package.size(), package) == 0 &&
             command[package.size()] == ':');
    }
    std::vector<TrackedProcess> update(const std::string& package,
                                      const std::vector<TrackedProcess>& all) {
        std::unordered_map<int, uint64_t> next;
        for (const auto& p : all) {
            auto old = live_.find(p.pid);
            if (p.starttime && (matches(package, p.command) ||
                (old != live_.end() && old->second == p.starttime)))
                next.emplace(p.pid, p.starttime);
        }
        // A reparented descendant stays tracked until its own generation exits.
        // Never inherit from a recycled parent PID with a different starttime.
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto& p : all) {
                auto parent = next.find(p.parent);
                if (p.starttime && parent != next.end() &&
                    p.starttime >= parent->second && !next.count(p.pid)) {
                    next.emplace(p.pid, p.starttime);
                    changed = true;
                }
            }
        }
        live_ = std::move(next);
        std::vector<TrackedProcess> result;
        for (const auto& p : all)
            if (live_.count(p.pid)) result.push_back(p);
        std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
            return a.starttime == b.starttime ? a.pid < b.pid : a.starttime < b.starttime;
        });
        return result;
    }
    bool contains(int pid, uint64_t starttime) const {
        auto it = live_.find(pid);
        return it != live_.end() && it->second == starttime;
    }
private:
    std::unordered_map<int, uint64_t> live_;
};
