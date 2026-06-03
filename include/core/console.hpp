#pragma once

#include <string>
#include <string_view>

namespace kld::console
{
    // Initialize the console styling engine.
    // On Windows, this will attempt to enable Virtual Terminal Processing.
    void init();

    // Query or explicitly set whether colors are enabled.
    void set_color_enabled(bool enabled);
    bool is_color_enabled();

    // Standard ANSI formatting helpers
    std::string reset();
    std::string bold(std::string_view text);
    std::string dim(std::string_view text);

    // Standard foreground color helpers
    std::string red(std::string_view text);
    std::string green(std::string_view text);
    std::string yellow(std::string_view text);
    std::string blue(std::string_view text);
    std::string magenta(std::string_view text);
    std::string cyan(std::string_view text);
    std::string grey(std::string_view text);

    // Bright foreground color helpers
    std::string bright_red(std::string_view text);
    std::string bright_green(std::string_view text);
    std::string bright_yellow(std::string_view text);
    std::string bright_cyan(std::string_view text);

    // Contextual/Semantic color helpers
    std::string colorize_risk(int score, std::string_view text);
    std::string colorize_suspicious(bool suspicious, std::string_view text);
}
