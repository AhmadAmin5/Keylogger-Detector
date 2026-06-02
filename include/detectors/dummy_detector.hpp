#pragma once

#include "core/i_detector.hpp"

namespace kld
{
    class DummyDetector final : public IDetector
    {
    public:
        std::string name() const override;
        DetectionResult scan() const override;
    };
}