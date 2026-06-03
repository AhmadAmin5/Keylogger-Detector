#include "detectors/network_beacon_detector.hpp"
#include "detectors/windows_inspection.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace kld
{
    namespace
    {
        bool is_interesting_remote(const std::wstring& address, std::uint16_t port)
        {
            if (port == 8443 || port == 8080 || port == 9000 || port == 4444)
            {
                return true;
            }

            if ((port >= 8000 && port <= 8999) && !address.empty())
            {
                return true;
            }

            return false;
        }

        bool is_private_ipv4(const std::wstring& address)
        {
            int a = 0, b = 0, c = 0, d = 0;
            if (swscanf(address.c_str(), L"%d.%d.%d.%d", &a, &b, &c, &d) != 4)
            {
                return false;
            }

            if (a == 10)
            {
                return true;
            }

            if (a == 192 && b == 168)
            {
                return true;
            }

            if (a == 172 && b >= 16 && b <= 31)
            {
                return true;
            }

            if (a == 169 && b == 254)
            {
                return true;
            }

            return false;
        }

        std::string state_to_text(std::uint32_t state)
        {
            switch (state)
            {
            case 1:  return "CLOSED";
            case 2:  return "LISTEN";
            case 3:  return "SYN_SENT";
            case 4:  return "SYN_RCVD";
            case 5:  return "ESTABLISHED";
            case 6:  return "FIN_WAIT1";
            case 7:  return "FIN_WAIT2";
            case 8:  return "CLOSE_WAIT";
            case 9:  return "CLOSING";
            case 10: return "LAST_ACK";
            case 11: return "TIME_WAIT";
            case 12: return "DELETE_TCB";
            default: return "UNKNOWN";
            }
        }

        std::string process_name_for_pid(std::uint32_t pid)
        {
            for (const auto& proc : enumerate_processes())
            {
                if (proc.pid == pid)
                {
                    return wide_to_utf8(proc.imageName);
                }
            }
            return "unknown";
        }

        std::string join_lines(const std::vector<std::string>& lines)
        {
            std::ostringstream oss;
            for (std::size_t i = 0; i < lines.size(); ++i)
            {
                if (i != 0)
                {
                    oss << "\n";
                }
                oss << lines[i];
            }
            return oss.str();
        }

        bool is_legit_process(const std::string& imageName)
        {
            std::string lowerName = imageName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });

            const std::vector<std::string> excluded_names = {
                "chrome.exe",
                "msedge.exe",
                "msedgewebview2.exe",
                "explorer.exe",
                "conhost.exe",
                "windefend.exe",
                "rtkauduservice64.exe",
                "widgets.exe",
                "fnhotkeyutility.exe",
                "trafficmonitor.exe",
                "shellhost.exe",
                "notepad.exe",
                "node.exe",
                "esrv.exe",
                "lenovovantage",
                "antigravity ide.exe",
                "windowsterminal.exe",
                "openconsole.exe"
            };

            for (const auto& name : excluded_names)
            {
                if (lowerName.find(name) != std::string::npos)
                {
                    return true;
                }
            }
            return false;
        }
    }

    std::string NetworkBeaconDetector::name() const
    {
        return "Network Beacon Detector";
    }

    DetectionResult NetworkBeaconDetector::scan(OutputMode mode) const
    {
        DetectionResult result;
        result.detectorName = name();

        const DWORD selfPid = GetCurrentProcessId();
        const std::string selfName = wide_to_utf8(get_current_process_image_name());
        const auto connections = enumerate_tcp_connections();

        std::vector<std::string> evidence;
        bool foundSuspicious = false;
        int score = 0;

        for (const auto& conn : connections)
        {
            if (conn.pid == selfPid)
            {
                continue;
            }

            if (conn.state != 5)
            {
                continue;
            }

            const bool privateRemote = is_private_ipv4(conn.remoteAddress);
            const bool interestingPort = is_interesting_remote(conn.remoteAddress, conn.remotePort);

            if (!privateRemote && !interestingPort)
            {
                continue;
            }

            std::string procName = process_name_for_pid(conn.pid);
            std::string lowerProcName = procName;
            std::transform(lowerProcName.begin(), lowerProcName.end(), lowerProcName.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (lowerProcName == selfName)
            {
                continue;
            }

            if (mode == OutputMode::SuspiciousScan && is_legit_process(procName))
            {
                continue;
            }

            foundSuspicious = true;
            score = std::max(score, (conn.remotePort == 8443) ? 90 : 70);

            std::ostringstream line;
            line << "PID " << conn.pid
                 << " | " << procName
                 << " | " << wide_to_utf8(conn.localAddress) << ":" << conn.localPort
                 << " -> " << wide_to_utf8(conn.remoteAddress) << ":" << conn.remotePort
                 << " | state=" << state_to_text(conn.state);

            evidence.push_back(line.str());
        }

        if (foundSuspicious)
        {
            result.suspicious = true;
            result.riskScore = score;
            result.details = "Suspicious outbound beacon-style TCP activity found:\n" + join_lines(evidence);
        }
        else
        {
            result.suspicious = false;
            result.riskScore = 0;
            result.details = "No suspicious established outbound TCP connections were found.";
        }

        return result;
    }
}