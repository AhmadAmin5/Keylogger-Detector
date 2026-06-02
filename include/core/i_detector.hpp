#pragma once

#include "core/detection_result.hpp"
#include <string>

namespace kld
{
    class IDetector
    {
    public:
        virtual ~IDetector() = default;

        // Human-readable detector name
        virtual std::string name() const = 0;

        virtual DetectionResult scan() const = 0;
    };
}