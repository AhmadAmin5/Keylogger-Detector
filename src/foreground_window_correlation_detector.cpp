#include "detectors/foreground_window_correlation_detector.hpp"
#include "detectors/windows_inspection.hpp"

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace kld
{
    namespace
    {
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

        bool is_legit_process(const std::wstring& imageName)
        {
            std::wstring lowerName = imageName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), [](wchar_t c) {
                return std::towlower(c);
            });

            const std::vector<std::wstring> excluded_names = {
                L"chrome.exe",
                L"msedge.exe",
                L"msedgewebview2.exe",
                L"explorer.exe",
                L"conhost.exe",
                L"windefend.exe",
                L"rtkauduservice64.exe",
                L"widgets.exe",
                L"fnhotkeyutility.exe",
                L"trafficmonitor.exe",
                L"shellhost.exe",
                L"notepad.exe",
                L"node.exe",
                L"esrv.exe",
                L"lenovovantage",
                L"windowsterminal.exe",
                L"openconsole.exe",
                L"idman.exe",
                L"git.exe",
                L"git-remote-https.exe",
                L"git-remote-http.exe"
            };

            for (const auto& name : excluded_names)
            {
                if (lowerName.find(name) != std::wstring::npos)
                {
                    return true;
                }
            }
            return false;
        }

        void append_markers(std::vector<std::string>& out,
                            const std::vector<std::string>& in)
        {
            out.insert(out.end(), in.begin(), in.end());
        }
    }

    std::string ForegroundWindowCorrelationDetector::name() const
    {
        return "Foreground Window Correlation Detector";
    }

    DetectionResult ForegroundWindowCorrelationDetector::scan(OutputMode mode) const
    {
        DetectionResult result;
        result.detectorName = name();

        const DWORD selfPid = GetCurrentProcessId();
        const std::wstring selfName = get_current_process_image_name();
        const auto processes = enumerate_processes();

        const std::vector<std::string> foregroundMarkers =
        {
            "GetForegroundWindow"
        };

        const std::vector<std::string> windowTextMarkers =
        {
            "GetWindowTextA",
            "GetWindowTextW",
            "GetWindowTextLengthA",
            "GetWindowTextLengthW"
        };

        const std::vector<std::string> keyPollingMarkers =
        {
            "GetAsyncKeyState",
            "GetKeyState"
        };

        std::vector<std::string> evidence;
        bool foundSuspiciousProcess = false;
        int score = 0;

        for (const auto& proc : processes)
        {
            if (proc.pid == selfPid)
            {
                continue;
            }

            std::wstring lowerName = proc.imageName;
            std::transform(
                lowerName.begin(),
                lowerName.end(),
                lowerName.begin(),
                [](wchar_t c)
                {
                    return std::towlower(c);
                });

            if (lowerName == selfName)
            {
                continue;
            }

            if (proc.imagePath.empty())
            {
                continue;
            }

            std::vector<std::string> foregroundHits;
            std::vector<std::string> windowTextHits;
            std::vector<std::string> keyPollingHits;

            const bool hasForeground =
                file_contains_markers(proc.imagePath, foregroundMarkers, &foregroundHits);
            const bool hasWindowText =
                file_contains_markers(proc.imagePath, windowTextMarkers, &windowTextHits);
            const bool hasKeyPolling =
                file_contains_markers(proc.imagePath, keyPollingMarkers, &keyPollingHits);

            const bool correlationHit = hasForeground && hasWindowText && hasKeyPolling;
            if (!correlationHit)
            {
                continue;
            }

            const bool legitProcess = is_legit_process(proc.imageName);
            if (!legitProcess)
            {
                foundSuspiciousProcess = true;
            }

            if (mode == OutputMode::SuspiciousScan && legitProcess)
            {
                continue;
            }

            std::vector<std::string> hits;
            append_markers(hits, foregroundHits);
            append_markers(hits, windowTextHits);
            append_markers(hits, keyPollingHits);

            int localScore = 0;
            if (hasForeground)
            {
                localScore += 30;
            }
            if (hasWindowText)
            {
                localScore += 25;
            }
            if (hasKeyPolling)
            {
                localScore += 35;
            }

            score = std::max(score, std::min(localScore, 95));

            std::ostringstream line;
            line << "PID "
                 << proc.pid
                 << " | "
                 << wide_to_utf8(proc.imageName)
                 << " | foreground-window correlation markers: ";

            for (std::size_t i = 0; i < hits.size(); ++i)
            {
                if (i != 0)
                {
                    line << ", ";
                }

                line << hits[i];
            }

            evidence.push_back(line.str());
        }

        if (foundSuspiciousProcess)
        {
            result.suspicious = true;
            result.riskScore = std::max(score, 70);

            if (!evidence.empty())
            {
                result.details =
                    "Foreground-window + keyboard-polling correlation matched:\n" +
                    join_lines(evidence);
            }
            else
            {
                result.details =
                    "Suspicious non-legitimate process detected.";
            }
        }
        else
        {
            result.suspicious = false;
            result.riskScore = 0;
            result.details =
                "No suspicious foreground-window correlation markers were found.";
        }

        return result;
    }
}
