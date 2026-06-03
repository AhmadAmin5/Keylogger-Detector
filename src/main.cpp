#include "core/detector_registry.hpp"
#include "detectors/keyboard_hook_heuristic_detector.hpp"
#include "detectors/network_beacon_detector.hpp"
#include "detectors/foreground_window_correlation_detector.hpp"
#include "detectors/python_artifact_detector.hpp"
#include "detectors/pyinstaller_detector.hpp"
#include "core/console.hpp"
#include "helper.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <conio.h>
#include <future>
#include <chrono>
#include <thread>

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
    console::set_cursor_visible(false);

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
    registry.add(std::make_unique<ForegroundWindowCorrelationDetector>());
    registry.add(std::make_unique<KeyboardHookHeuristicDetector>());

    std::vector<DetectionResult> results;
    results.reserve(registry.detectors().size());

    for (const auto& detector : registry.detectors())
    {
        std::string name = detector->name();
        IDetector* rawDetector = detector.get();

        // Run the scan asynchronously on a background thread
        auto futureResult = std::async(std::launch::async, [rawDetector, mode]() {
            return rawDetector->scan(mode);
        });

        // Spinner animation loop
        const char spinner[] = {'|', '/', '-', '\\'};
        int spinnerIndex = 0;

        while (futureResult.wait_for(std::chrono::milliseconds(80)) != std::future_status::ready)
        {
            std::cout << "\r" << console::cyan("[~]") 
                      << " Scanning with " << console::bold(name) 
                      << "... " << console::bright_cyan(std::string(1, spinner[spinnerIndex])) << std::flush;
            spinnerIndex = (spinnerIndex + 1) % 4;
        }

        // Clear the spinner / loading line completely
        std::cout << "\r" << std::string(name.length() + 30, ' ') << "\r" << std::flush;

        // Retrieve result
        DetectionResult result = futureResult.get();

        if (result.detectorName.empty())
        {
            result.detectorName = name;
        }

        print_result(result);
        results.push_back(result);
    }

    print_summary(results);

    std::cout << console::grey("\nPress any key to exit...");
    getch();
    console::set_cursor_visible(true);
    return 0;
}
