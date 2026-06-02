#pragma once

#include "core/i_detector.hpp"

namespace kld
{
    class KeyboardHookHeuristicDetector final : public IDetector
    {
    public:
        std::string name() const override;
        DetectionResult scan() const override;
    };
}