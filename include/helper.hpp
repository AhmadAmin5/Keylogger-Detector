#pragma once

#include "core/detection_result.hpp"
#include <vector>

namespace kld
{
    void print_banner();
    void print_result(const DetectionResult& result);
    void print_summary(const std::vector<DetectionResult>& results);

    std::string risk_label(int score);
    int clamp_score(int score);
}