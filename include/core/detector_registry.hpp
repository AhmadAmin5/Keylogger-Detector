#pragma once

#include "core/i_detector.hpp"

#include <memory>
#include <vector>

namespace kld
{
    class DetectorRegistry
    {
    public:
        void add(std::unique_ptr<IDetector> detector);

        [[nodiscard]] const std::vector<std::unique_ptr<IDetector>>& detectors() const;

    private:
        std::vector<std::unique_ptr<IDetector>> m_detectors;
    };
}
