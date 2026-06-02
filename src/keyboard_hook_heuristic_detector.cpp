#include "detectors/keyboard_hook_heuristic_detector.hpp"
#include "detectors/windows_inspection.hpp"

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
    }

    std::string KeyboardHookHeuristicDetector::name() const
    {
        return "Keyboard Hook Heuristic Detector";
    }

    DetectionResult KeyboardHookHeuristicDetector::scan() const
    {
        DetectionResult result;
        result.detectorName = name();

        const DWORD selfPid = GetCurrentProcessId();

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
        int score = 0;

        for (const auto& proc : processes)
        {
            if (proc.pid == selfPid)
            {
                continue;
            }

            std::vector<std::string> hits;
            if (!proc.imagePath.empty() && file_contains_markers(proc.imagePath, markers, &hits))
            {
                int localScore = 0;
                for (const auto& hit : hits)
                {
                    if (hit == "WH_KEYBOARD_LL" || hit == "SetWindowsHookEx" || hit == "GetAsyncKeyState")
                    {
                        localScore += 30;
                    }
                    else if (hit == "pynput.keyboard" || hit == "keyboard.Listener")
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
                line << "PID " << proc.pid
                     << " | " << wide_to_utf8(proc.imageName)
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

        if (!evidence.empty())
        {
            result.suspicious = true;
            result.riskScore = std::max(score, 65);
            result.details = "Keyboard-hook / key-capture heuristic matched:\n" + join_lines(evidence);
        }
        else
        {
            result.suspicious = false;
            result.riskScore = 0;
            result.details = "No keyboard-hook heuristic markers were found in running processes.";
        }

        return result;
    }
}