#include "detectors/windows_inspection.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

namespace kld
{
    namespace
    {
        bool contains_bytes(const std::vector<std::uint8_t>& haystack,
                            const std::vector<std::uint8_t>& needle)
        {
            if (needle.empty() || haystack.size() < needle.size())
            {
                return false;
            }

            return std::search(
                haystack.begin(),
                haystack.end(),
                needle.begin(),
                needle.end()) != haystack.end();
        }

        std::vector<std::uint8_t> ascii_to_utf16le_bytes(const std::string& s)
        {
            std::vector<std::uint8_t> out;
            out.reserve(s.size() * 2);

            for (unsigned char c : s)
            {
                out.push_back(c);
                out.push_back(0x00);
            }

            return out;
        }

        std::wstring endpoint_to_wstring(const sockaddr_in& addr)
        {
            wchar_t buffer[64]{};
            if (InetNtopW(AF_INET, const_cast<in_addr*>(&addr.sin_addr), buffer, 64) == nullptr)
            {
                return L"unknown";
            }

            return buffer;
        }
    }

    std::string wide_to_utf8(const std::wstring& text)
    {
        if (text.empty())
        {
            return {};
        }

        const int requiredSize = WideCharToMultiByte(
            CP_UTF8,
            0,
            text.c_str(),
            -1,
            nullptr,
            0,
            nullptr,
            nullptr);

        if (requiredSize <= 0)
        {
            return {};
        }

        std::string out(static_cast<std::size_t>(requiredSize - 1), '\0');
        WideCharToMultiByte(
            CP_UTF8,
            0,
            text.c_str(),
            -1,
            out.data(),
            requiredSize,
            nullptr,
            nullptr);

        return out;
    }

    std::vector<ProcessRecord> enumerate_processes()
    {
        std::vector<ProcessRecord> processes;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return processes;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                ProcessRecord rec;
                rec.pid = entry.th32ProcessID;
                rec.imageName = entry.szExeFile;

                HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, rec.pid);
                if (processHandle)
                {
                    std::wstring path(32768, L'\0');
                    DWORD size = static_cast<DWORD>(path.size());

                    if (QueryFullProcessImageNameW(processHandle, 0, path.data(), &size))
                    {
                        path.resize(size);
                        rec.imagePath = std::move(path);
                    }

                    CloseHandle(processHandle);
                }

                processes.push_back(std::move(rec));
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return processes;
    }

    std::wstring get_current_process_image_name()
    {
        wchar_t path[32768]{};
        if (GetModuleFileNameW(nullptr, path, 32768) == 0)
        {
            return L"app.exe";
        }
        std::wstring selfPath(path);
        std::size_t pos = selfPath.find_last_of(L"\\/");
        std::wstring name = (pos == std::wstring::npos) ? selfPath : selfPath.substr(pos + 1);
        std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) {
            return std::towlower(c);
        });
        return name;
    }

    std::vector<TcpConnectionRecord> enumerate_tcp_connections()
    {
        std::vector<TcpConnectionRecord> connections;

        DWORD size = 0;
        DWORD ret = GetExtendedTcpTable(
            nullptr,
            &size,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0);

        if (ret != ERROR_INSUFFICIENT_BUFFER || size == 0)
        {
            return connections;
        }

        std::vector<std::uint8_t> buffer(size);
        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

        ret = GetExtendedTcpTable(
            table,
            &size,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0);

        if (ret != NO_ERROR)
        {
            return connections;
        }

        for (DWORD i = 0; i < table->dwNumEntries; ++i)
        {
            const auto& row = table->table[i];

            sockaddr_in localAddr{};
            localAddr.sin_family = AF_INET;
            localAddr.sin_addr.S_un.S_addr = row.dwLocalAddr;
            localAddr.sin_port = 0;

            sockaddr_in remoteAddr{};
            remoteAddr.sin_family = AF_INET;
            remoteAddr.sin_addr.S_un.S_addr = row.dwRemoteAddr;
            remoteAddr.sin_port = 0;

            TcpConnectionRecord rec;
            rec.pid = row.dwOwningPid;
            rec.localAddress = endpoint_to_wstring(localAddr);
            rec.remoteAddress = endpoint_to_wstring(remoteAddr);
            rec.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            rec.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
            rec.state = row.dwState;

            connections.push_back(std::move(rec));
        }

        return connections;
    }

    bool file_contains_markers(
        const std::wstring& path,
        const std::vector<std::string>& asciiMarkers,
        std::vector<std::string>* matchedMarkers)
    {
        if (matchedMarkers)
        {
            matchedMarkers->clear();
        }

        if (path.empty())
        {
            return false;
        }

        HANDLE file = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        LARGE_INTEGER fileSize{};
        if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0)
        {
            CloseHandle(file);
            return false;
        }

        if (fileSize.QuadPart > 100LL * 1024LL * 1024LL)
        {
            CloseHandle(file);
            return false;
        }

        std::vector<std::uint8_t> data(static_cast<std::size_t>(fileSize.QuadPart));
        DWORD totalRead = 0;

        while (totalRead < data.size())
        {
            DWORD bytesRead = 0;
            const DWORD toRead = static_cast<DWORD>(
                std::min<std::size_t>(data.size() - totalRead, 1u << 20));

            if (!ReadFile(file, data.data() + totalRead, toRead, &bytesRead, nullptr) || bytesRead == 0)
            {
                break;
            }

            totalRead += bytesRead;
        }

        CloseHandle(file);

        if (totalRead == 0)
        {
            return false;
        }

        data.resize(totalRead);

        bool anyMatch = false;

        for (const auto& marker : asciiMarkers)
        {
            const std::vector<std::uint8_t> ascii(marker.begin(), marker.end());
            const std::vector<std::uint8_t> utf16 = ascii_to_utf16le_bytes(marker);

            if (contains_bytes(data, ascii) || contains_bytes(data, utf16))
            {
                anyMatch = true;
                if (matchedMarkers)
                {
                    matchedMarkers->push_back(marker);
                }
            }
        }

        return anyMatch;
    }
}