#include "helper.hpp"
#include "core/console.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>

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
        std::cout << console::cyan("=====================================\n");
        std::cout << console::bold("   Keylogger Detector - Lab Project   \n");
        std::cout << console::cyan("=====================================\n\n");
    }

    void print_result(const DetectionResult& result)
    {
        std::cout << "[" << console::cyan("Detector") << "] " << console::bold(result.detectorName) << "\n";
        
        std::string suspiciousStr = result.suspicious ? "YES" : "NO";
        std::cout << "  Suspicious : " << console::colorize_suspicious(result.suspicious, suspiciousStr) << "\n";
        
        std::string riskStr = std::to_string(clamp_score(result.riskScore)) + " (" + risk_label(result.riskScore) + ")";
        std::cout << "  Risk Score : " << console::colorize_risk(result.riskScore, riskStr) << "\n";
        
        if (!result.details.empty())
        {
            std::cout << "  Details    : ";
            
            std::string details = result.details;
            std::size_t pos = details.find('\n');
            if (pos == std::string::npos)
            {
                // Single line detail
                if (result.suspicious)
                {
                    std::cout << console::bright_yellow(details) << "\n\n";
                }
                else
                {
                    std::cout << console::grey(details) << "\n\n";
                }
            }
            else
            {
                // Multi-line detail. First line is header, subsequent lines are lists (e.g. process lists).
                std::string header = details.substr(0, pos);
                std::string body = details.substr(pos + 1);
                
                if (result.suspicious)
                {
                    std::cout << console::bright_yellow(header) << "\n";
                }
                else
                {
                    std::cout << header << "\n";
                }

                // Split body by newline and indent to align under 'Details    : ' (15 spaces) in grey
                std::istringstream iss(body);
                std::string line;
                while (std::getline(iss, line))
                {
                    std::cout << "               " << console::grey(line) << "\n";
                }
                std::cout << "\n";
            }
        }
        else
        {
            std::cout << "  Details    : (none)\n\n";
        }
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

        std::string border = "=====================================\n";
        std::string divider = "-------------------------------------\n";

        if (anySuspicious)
        {
            std::cout << console::bright_red(border);
            std::cout << console::bold(console::bright_red("Summary (THREATS DETECTED)\n"));
            std::cout << console::bright_red(divider);
        }
        else
        {
            std::cout << console::bright_green(border);
            std::cout << console::bold(console::bright_green("Summary (SYSTEM CLEAN)\n"));
            std::cout << console::bright_green(divider);
        }

        std::cout << "  Detectors run : " << results.size() << "\n";
        
        std::string suspiciousStr = anySuspicious ? "YES" : "NO";
        std::cout << "  Any suspicious: " << console::colorize_suspicious(anySuspicious, suspiciousStr) << "\n";
        
        std::string riskStr = std::to_string(maxScore) + " (" + risk_label(maxScore) + ")";
        std::cout << "  Highest score : " << console::colorize_risk(maxScore, riskStr) << "\n";
        
        if (anySuspicious)
        {
            std::cout << console::bright_red(border);
        }
        else
        {
            std::cout << console::bright_green(border);
        }
    }
}