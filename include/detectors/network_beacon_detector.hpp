#pragma once

#include "core/i_detector.hpp"

namespace kld
{
    class NetworkBeaconDetector final : public IDetector
    {
    public:
        std::string name() const override;
        DetectionResult scan(OutputMode mode) const override;
    };
}