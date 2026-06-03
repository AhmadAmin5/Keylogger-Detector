#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace kld
{
    struct ProcessRecord
    {
        std::uint32_t pid{};
        std::wstring imageName;
        std::wstring imagePath;
    };

    struct TcpConnectionRecord
    {
        std::uint32_t pid{};
        std::wstring localAddress;
        std::uint16_t localPort{};
        std::wstring remoteAddress;
        std::uint16_t remotePort{};
        std::uint32_t state{};
    };

    std::vector<ProcessRecord> enumerate_processes();
    std::vector<TcpConnectionRecord> enumerate_tcp_connections();
    std::wstring get_current_process_image_name();

    bool file_contains_markers(
        const std::wstring& path,
        const std::vector<std::string>& asciiMarkers,
        std::vector<std::string>* matchedMarkers = nullptr);

    std::string wide_to_utf8(const std::wstring& text);
}