#include "core/detector_registry.hpp"
#include "detectors/keyboard_hook_heuristic_detector.hpp"
#include "detectors/network_beacon_detector.hpp"
#include "detectors/python_artifact_detector.hpp"
#include "detectors/pyinstaller_detector.hpp"
#include "helper.hpp"

#include <memory>
#include <vector>

int main()
{
    using namespace kld;

    print_banner();

    DetectorRegistry registry;
    registry.add(std::make_unique<PyInstallerDetector>());
    registry.add(std::make_unique<PythonArtifactDetector>());
    registry.add(std::make_unique<NetworkBeaconDetector>());
    registry.add(std::make_unique<KeyboardHookHeuristicDetector>());

    std::vector<DetectionResult> results;
    results.reserve(registry.detectors().size());

    for (const auto& detector : registry.detectors())
    {
        DetectionResult result = detector->scan();

        if (result.detectorName.empty())
        {
            result.detectorName = detector->name();
        }

        print_result(result);
        results.push_back(result);
    }

    print_summary(results);
    return 0;
}