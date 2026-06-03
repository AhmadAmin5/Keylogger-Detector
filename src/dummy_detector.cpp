#include "detectors/dummy_detector.hpp"

namespace kld
{
    std::string DummyDetector::name() const
    {
        return "Dummy Detector";
    }

    DetectionResult DummyDetector::scan(OutputMode mode) const
    {
        (void)mode;
        DetectionResult result;
        result.detectorName = name();
        result.suspicious = false;
        result.riskScore = 0;
        result.details = "Baseline detector is active. Replace this with a real technique detector.";
        return result;
    }
}