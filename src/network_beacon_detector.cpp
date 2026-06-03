#include "detectors/network_beacon_detector.hpp"
#include "detectors/windows_inspection.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace kld
{
    namespace
    {
        constexpr int OBSERVATION_SECONDS = 20;
        constexpr int SAMPLE_INTERVAL_MS = 500;
        constexpr int SAMPLE_COUNT =
            (OBSERVATION_SECONDS * 1000) / SAMPLE_INTERVAL_MS;

        constexpr std::uint32_t TCP_STATE_SYN_SENT = 3;
        constexpr std::uint32_t TCP_STATE_ESTABLISHED = 5;

        struct BeaconHit
        {
            std::uint32_t pid{};
            std::string processName;

            std::wstring localAddress;
            std::uint16_t localPort{};

            std::wstring remoteAddress;
            std::uint16_t remotePort{};

            std::uint32_t state{};

            bool legit{};
        };

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

        bool is_private_ipv4(const std::wstring& address)
        {
            int a = 0;
            int b = 0;
            int c = 0;
            int d = 0;

            if (swscanf(
                    address.c_str(),
                    L"%d.%d.%d.%d",
                    &a,
                    &b,
                    &c,
                    &d) != 4)
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

            if (a == 127)
            {
                return true;
            }

            return false;
        }

        bool is_interesting_port(std::uint16_t port)
        {
            if (port == 8443)
            {
                return true;
            }

            switch (port)
            {
            case 4444:
            case 5555:
            case 6666:
            case 7777:
            case 8080:
            case 8081:
            case 8088:
            case 9000:
            case 9001:
            case 9999:
                return true;
            default:
                break;
            }

            return (port >= 8000 && port <= 8999);
        }

        std::string process_name_for_pid(std::uint32_t pid)
        {
            const auto processes = enumerate_processes();

            for (const auto& proc : processes)
            {
                if (proc.pid == pid)
                {
                    return wide_to_utf8(proc.imageName);
                }
            }

            return "unknown";
        }

        bool is_legit_process(const std::string& imageName)
        {
            std::string name = imageName;

            std::transform(
                name.begin(),
                name.end(),
                name.begin(),
                [](unsigned char c)
                {
                    return static_cast<char>(std::tolower(c));
                });

            static const std::vector<std::string> whitelist =
            {
                "chrome.exe",
                "msedge.exe",
                "msedgewebview2.exe",
                "firefox.exe",
                "brave.exe",
                "opera.exe",

                "explorer.exe",
                "svchost.exe",
                "services.exe",
                "lsass.exe",
                "wininit.exe",
                "winlogon.exe",
                "dwm.exe",
                "taskhostw.exe",
                "sihost.exe",
                "searchhost.exe",
                "searchindexer.exe",

                "widgets.exe",
                "runtimebroker.exe",
                "textinputhost.exe",
                "startmenuexperiencehost.exe",
                "crossdeviceservice.exe",

                "windefend.exe",
                "securityhealthservice.exe",
                "securityhealthsystray.exe",

                "onedrive.exe",
                "teams.exe",
                "discord.exe",
                "steam.exe",
                "spotify.exe",
                "warp-svc.exe",

                "node.exe",
                "code.exe",
                "language_server_windows_x64.exe",
                "windowsterminal.exe",
                "openconsole.exe",
                "conhost.exe",
                "ssh.exe",

                "trafficmonitor.exe",
                "rtkauduservice64.exe",
                "lenovovantage",
                "esrv.exe"
            };

            for (const auto& entry : whitelist)
            {
                if (name.find(entry) != std::string::npos)
                {
                    return true;
                }
            }

            return false;
        }

        int calculate_risk(const BeaconHit& hit)
        {
            int score = 50;

            if (hit.remotePort == 8443)
            {
                score += 35;
            }
            else if (is_interesting_port(hit.remotePort))
            {
                score += 20;
            }

            if (hit.state == TCP_STATE_SYN_SENT)
            {
                score += 10;
            }

            if (!is_private_ipv4(hit.remoteAddress))
            {
                score += 10;
            }

            return std::min(score, 100);
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

        std::set<std::string> seenConnections;
        std::vector<BeaconHit> hits;

        int maxRisk = 0;
        bool foundNonLegit = false;

        for (int sample = 0; sample < SAMPLE_COUNT; ++sample)
        {
            const auto connections = enumerate_tcp_connections();

            for (const auto& conn : connections)
            {
                if (conn.pid == selfPid)
                {
                    continue;
                }

                if (conn.state != TCP_STATE_ESTABLISHED &&
                    conn.state != TCP_STATE_SYN_SENT)
                {
                    continue;
                }

                const bool interesting =
                    is_interesting_port(conn.remotePort) ||
                    !is_private_ipv4(conn.remoteAddress);

                if (!interesting)
                {
                    continue;
                }

                const std::string procName =
                    process_name_for_pid(conn.pid);

                const bool legit =
                    is_legit_process(procName);

                std::ostringstream key;
                key << conn.pid
                    << '|'
                    << wide_to_utf8(conn.remoteAddress)
                    << '|'
                    << conn.remotePort
                    << '|'
                    << conn.state;

                if (!seenConnections.insert(key.str()).second)
                {
                    continue;
                }

                BeaconHit hit;
                hit.pid = conn.pid;
                hit.processName = procName;
                hit.localAddress = conn.localAddress;
                hit.localPort = conn.localPort;
                hit.remoteAddress = conn.remoteAddress;
                hit.remotePort = conn.remotePort;
                hit.state = conn.state;
                hit.legit = legit;

                hits.push_back(hit);

                if (!legit)
                {
                    foundNonLegit = true;
                    maxRisk = std::max(maxRisk, calculate_risk(hit));
                }
            }

            if (sample + 1 < SAMPLE_COUNT)
            {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(
                        SAMPLE_INTERVAL_MS));
            }
        }

        std::vector<std::string> outputLines;

        for (const auto& hit : hits)
        {
            if (mode == OutputMode::SuspiciousScan &&
                hit.legit)
            {
                continue;
            }

            std::ostringstream line;

            line
                << "PID " << hit.pid
                << " | " << hit.processName
                << (hit.legit ? " [WHITELISTED]" : " [NON-LEGIT]")
                << " | "
                << wide_to_utf8(hit.localAddress)
                << ":" << hit.localPort
                << " -> "
                << wide_to_utf8(hit.remoteAddress)
                << ":" << hit.remotePort
                << " | state="
                << state_to_text(hit.state);

            outputLines.push_back(line.str());
        }

        result.suspicious = foundNonLegit;
        result.riskScore = foundNonLegit ? maxRisk : 0;

        if (outputLines.empty())
        {
            result.details =
                "No beacon-style TCP activity observed during the 20-second observation window.";
        }
        else
        {
            result.details =
                "Beacon-style TCP activity observed over 20 seconds:\n" +
                join_lines(outputLines);
        }

        return result;
    }
}
