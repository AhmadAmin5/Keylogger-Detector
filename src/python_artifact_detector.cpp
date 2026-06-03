#include "detectors/python_artifact_detector.hpp"
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
                L"openconsole.exe"
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

    std::string PythonArtifactDetector::name() const
    {
        return "Python Artifact Detector";
    }

    DetectionResult PythonArtifactDetector::scan(OutputMode mode) const
{
    DetectionResult result;
    result.detectorName = name();

    const DWORD selfPid = GetCurrentProcessId();
    const std::wstring selfName = get_current_process_image_name();

    const std::vector<std::string> markers =
    {
        "pynput",
        "pynput.keyboard",
        "requests",
        "urllib3",
        "certifi",
        "C2_URL",
        "verify=False",
        "keyboard.Listener",
        "on_press",
        "threading",
        "buffer = []"
    };

    const auto processes = enumerate_processes();

    std::vector<std::string> evidence;
    bool foundSuspiciousProcess = false;

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
            // Detection logic (independent of output mode)
            //
            if (!legitProcess)
            {
                foundSuspiciousProcess = true;
            }

            //
            // Output filtering
            //
            if (mode == OutputMode::SuspiciousScan)
            {
                if (legitProcess)
                {
                    continue;
                }
            }

            std::ostringstream line;

            line << "PID "
                 << proc.pid
                 << " | "
                 << wide_to_utf8(proc.imageName)
                 << " | Python/package indicators: ";

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
    // Final result
    //
    if (foundSuspiciousProcess)
    {
        result.suspicious = true;
        result.riskScore = 75;

        if (!evidence.empty())
        {
            result.details =
                "Python keylogger-style artifacts found:\n" +
                join_lines(evidence);
        }
        else
        {
            result.details =
                "Suspicious non-legitimate process detected but hidden by the current output mode.";
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
}}