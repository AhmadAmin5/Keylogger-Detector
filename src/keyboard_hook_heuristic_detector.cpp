#include "detectors/keyboard_hook_heuristic_detector.hpp"
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
    }

    std::string KeyboardHookHeuristicDetector::name() const
    {
        return "Keyboard Hook Heuristic Detector";
    }

    DetectionResult KeyboardHookHeuristicDetector::scan(OutputMode mode) const
    {
        DetectionResult result;
        result.detectorName = name();

        const DWORD selfPid = GetCurrentProcessId();
        const std::wstring selfName = get_current_process_image_name();

        const std::vector<std::string> markers =
        {
            "GetAsyncKeyState",
            "SetWindowsHookEx",
            "WH_KEYBOARD_LL",
            "GetKeyState",
            "pynput.keyboard",
            "keyboard.Listener",
            "on_press",
            "Listener"
        };

        const auto processes = enumerate_processes();

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

            std::vector<std::string> hits;

            if (!proc.imagePath.empty() &&
                file_contains_markers(proc.imagePath, markers, &hits))
            {
                const bool legitProcess = is_legit_process(proc.imageName);

                //
                // Detection logic
                //
                if (!legitProcess)
                {
                    foundSuspiciousProcess = true;
                }

                //
                // Output filtering only
                //
                if (mode == OutputMode::SuspiciousScan)
                {
                    if (legitProcess)
                    {
                        continue;
                    }
                }

                int localScore = 0;

                for (const auto& hit : hits)
                {
                    if (hit == "WH_KEYBOARD_LL" ||
                        hit == "SetWindowsHookEx" ||
                        hit == "GetAsyncKeyState")
                    {
                        localScore += 30;
                    }
                    else if (hit == "pynput.keyboard" ||
                            hit == "keyboard.Listener")
                    {
                        localScore += 20;
                    }
                    else
                    {
                        localScore += 10;
                    }
                }

                score = std::max(score, std::min(localScore, 95));

                std::ostringstream line;

                line << "PID "
                    << proc.pid
                    << " | "
                    << wide_to_utf8(proc.imageName)
                    << " | keyboard-capture indicators: ";

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
        }

        //
        // Final verdict
        //
        if (foundSuspiciousProcess)
        {
            result.suspicious = true;
            result.riskScore = std::max(score, 65);

            if (!evidence.empty())
            {
                result.details =
                    "Keyboard-hook / key-capture heuristic matched:\n" +
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
                "No suspicious non-legitimate processes were found.";
        }

        return result;
    }
}