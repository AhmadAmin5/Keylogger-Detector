#include "core/console.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif

#include <iostream>

namespace kld::console
{
    static bool g_color_enabled = true;

    void init()
    {
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE)
        {
            DWORD dwMode = 0;
            if (GetConsoleMode(hOut, &dwMode))
            {
                dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                if (!SetConsoleMode(hOut, dwMode))
                {
                    // If we cannot enable virtual terminal processing, turn off color
                    g_color_enabled = false;
                }
            }
            else
            {
                g_color_enabled = false;
            }
        }
        else
        {
            g_color_enabled = false;
        }
#endif
    }

    void set_color_enabled(bool enabled)
    {
        g_color_enabled = enabled;
    }

    bool is_color_enabled()
    {
        return g_color_enabled;
    }

    // Helper utility to wrap text in an ANSI sequence
    static std::string wrap(std::string_view text, std::string_view code)
    {
        if (!g_color_enabled || text.empty())
        {
            return std::string(text);
        }
        return std::string(code) + std::string(text) + "\033[0m";
    }

    std::string reset()
    {
        return g_color_enabled ? "\033[0m" : "";
    }

    std::string bold(std::string_view text)
    {
        return wrap(text, "\033[1m");
    }

    std::string dim(std::string_view text)
    {
        return wrap(text, "\033[2m");
    }

    std::string red(std::string_view text)
    {
        return wrap(text, "\033[31m");
    }

    std::string green(std::string_view text)
    {
        return wrap(text, "\033[32m");
    }

    std::string yellow(std::string_view text)
    {
        return wrap(text, "\033[33m");
    }

    std::string blue(std::string_view text)
    {
        return wrap(text, "\033[34m");
    }

    std::string magenta(std::string_view text)
    {
        return wrap(text, "\033[35m");
    }

    std::string cyan(std::string_view text)
    {
        return wrap(text, "\033[36m");
    }

    std::string grey(std::string_view text)
    {
        return wrap(text, "\033[90m");
    }

    std::string bright_red(std::string_view text)
    {
        return wrap(text, "\033[91m");
    }

    std::string bright_green(std::string_view text)
    {
        return wrap(text, "\033[92m");
    }

    std::string bright_yellow(std::string_view text)
    {
        return wrap(text, "\033[93m");
    }

    std::string bright_cyan(std::string_view text)
    {
        return wrap(text, "\033[96m");
    }

    std::string colorize_risk(int score, std::string_view text)
    {
        if (score == 0)
        {
            return green(text);
        }
        else if (score <= 25)
        {
            return blue(text);
        }
        else if (score <= 50)
        {
            return cyan(text);
        }
        else if (score <= 75)
        {
            return bright_yellow(text);
        }
        else
        {
            return bold(bright_red(text));
        }
    }

    std::string colorize_suspicious(bool suspicious, std::string_view text)
    {
        if (suspicious)
        {
            return bold(bright_red(text));
        }
        return green(text);
    }
}
