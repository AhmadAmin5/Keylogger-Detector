#include "core/detector_registry.hpp"

namespace kld
{
    void DetectorRegistry::add(std::unique_ptr<IDetector> detector)
    {
        m_detectors.emplace_back(std::move(detector));
    }

    const std::vector<std::unique_ptr<IDetector>>& DetectorRegistry::detectors() const
    {
        return m_detectors;
    }
}
