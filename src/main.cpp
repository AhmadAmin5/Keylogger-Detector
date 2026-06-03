#include "core/detector_registry.hpp"
#include "detectors/keyboard_hook_heuristic_detector.hpp"
#include "detectors/network_beacon_detector.hpp"
#include "detectors/python_artifact_detector.hpp"
#include "detectors/pyinstaller_detector.hpp"
#include "core/console.hpp"
#include "helper.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <conio.h>

int main()
{
    using namespace kld;

    console::init();
    print_banner();

    std::cout << console::bold("Select scan mode:\n");
    std::cout << "1. " << console::cyan("Full scan") << " (shows all outputs)\n";
    std::cout << "2. " << console::bright_cyan("Suspicious scan") << " (shows filtered outputs, recommended)\n";
    std::cout << "Choice [1/2, default: 2]: ";
    std::string choice;
    std::getline(std::cin, choice);

    OutputMode mode = OutputMode::SuspiciousScan;
    if (choice == "1")
    {
        mode = OutputMode::FullScan;
        std::cout << "\nRunning " << console::bold(console::cyan("Full Scan")) << "...\n\n";
    }
    else
    {
        mode = OutputMode::SuspiciousScan;
        std::cout << "\nRunning " << console::bold(console::bright_cyan("Suspicious Scan")) << "...\n\n";
    }

    DetectorRegistry registry;
    registry.add(std::make_unique<PyInstallerDetector>());
    registry.add(std::make_unique<PythonArtifactDetector>());
    registry.add(std::make_unique<NetworkBeaconDetector>());
    registry.add(std::make_unique<KeyboardHookHeuristicDetector>());

    std::vector<DetectionResult> results;
    results.reserve(registry.detectors().size());

    for (const auto& detector : registry.detectors())
    {
        DetectionResult result = detector->scan(mode);

        if (result.detectorName.empty())
        {
            result.detectorName = detector->name();
        }

        print_result(result);
        results.push_back(result);
    }

    print_summary(results);

    std::cout << console::grey("\nPress any key to exit...");
    getch();
    return 0;
}