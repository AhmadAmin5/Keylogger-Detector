#include "helper.hpp"
#include "detectors/dummy_detector.hpp"

#include <memory>
#include <vector>

int main()
{
    using namespace kld;

    print_banner();

    std::vector<std::unique_ptr<IDetector>> detectors;
    detectors.emplace_back(std::make_unique<DummyDetector>());

    std::vector<DetectionResult> results;
    results.reserve(detectors.size());

    for (const auto& detector : detectors)
    {
        DetectionResult result = detector->scan();

        // Safety net: if a detector forgot to set its name
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