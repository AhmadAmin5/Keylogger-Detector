#include "core/detector_registry.hpp"
#include "detectors/dummy_detector.hpp"
#include "helper.hpp"

#include <memory>
#include <vector>

int main()
{
    using namespace kld;

    print_banner();

    DetectorRegistry registry;
    registry.add(std::make_unique<DummyDetector>());

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