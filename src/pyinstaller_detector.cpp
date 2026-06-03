#include "detectors/pyinstaller_detector.hpp"
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
                L"lenovovantage"
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

    std::string PyInstallerDetector::name() const
    {
        return "PyInstaller Detector";
    }

    DetectionResult PyInstallerDetector::scan(OutputMode mode) const
    {
        DetectionResult result;
        result.detectorName = name();

        const DWORD selfPid = GetCurrentProcessId();

        const std::vector<std::string> markers =
        {
            "PyInstaller",
            "pyi-windows-manifest-filename",
            "pyiboot01_bootstrap",
            "pyimod01_archive",
            "pyimod02_importers",
            "MEIPASS",
            "_PYI",
            "pyi_rth"
        };

        const auto processes = enumerate_processes();
        std::vector<std::string> evidence;

        for (const auto& proc : processes)
        {
            if (proc.pid == selfPid)
            {
                continue;
            }

            if (mode == OutputMode::SuspiciousScan && is_legit_process(proc.imageName))
            {
                continue;
            }

            std::vector<std::string> hits;
            if (!proc.imagePath.empty() && file_contains_markers(proc.imagePath, markers, &hits))
            {
                std::ostringstream line;
                line << "PID " << proc.pid
                     << " | " << wide_to_utf8(proc.imageName)
                     << " | PyInstaller markers: ";

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
            result.riskScore = 85;
            result.details = "PyInstaller-style packed executable indicators found:\n" + join_lines(evidence);
        }
        else
        {
            result.suspicious = false;
            result.riskScore = 0;
            result.details = "No PyInstaller markers were found in running processes.";
        }

        return result;
    }
}