#include "helper.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>

namespace kld
{
    int clamp_score(int score)
    {
        return std::clamp(score, 0, 100);
    }

    std::string risk_label(int score)
    {
        score = clamp_score(score);

        if (score == 0)   return "Clean";
        if (score <= 25)  return "Low";
        if (score <= 50)  return "Moderate";
        if (score <= 75)  return "High";
        return "Critical";
    }

    void print_banner()
    {
        std::cout << "=====================================\n";
        std::cout << "   Keylogger Detector - Lab Project   \n";
        std::cout << "=====================================\n\n";
    }

    void print_result(const DetectionResult& result)
    {
        std::cout << "[Detector] " << result.detectorName << "\n";
        std::cout << "  Suspicious : " << (result.suspicious ? "YES" : "NO") << "\n";
        std::cout << "  Risk Score : " << clamp_score(result.riskScore)
                << " (" << risk_label(result.riskScore) << ")\n";
        std::cout << "  Details    : " << result.details << "\n\n";
    }

    void print_summary(const std::vector<DetectionResult>& results)
    {
        int maxScore = 0;
        bool anySuspicious = false;

        for (const auto& r : results)
        {
            maxScore = std::max(maxScore, clamp_score(r.riskScore));
            anySuspicious = anySuspicious || r.suspicious;
        }

        std::cout << "=====================================\n";
        std::cout << "Summary\n";
        std::cout << "-------------------------------------\n";
        std::cout << "Detectors run : " << results.size() << "\n";
        std::cout << "Any suspicious: " << (anySuspicious ? "YES" : "NO") << "\n";
        std::cout << "Highest score  : " << maxScore << " (" << risk_label(maxScore) << ")\n";
        std::cout << "=====================================\n";
    }
}