#pragma once

#include <string>

namespace kld
{
    struct DetectionResult
    {
        std::string detectorName;
        bool suspicious{false};
        int riskScore{0};
        std::string details;
    };
}