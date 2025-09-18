#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <thread>
#include <unordered_set>
#include <mutex>
#include <urlmon.h>

#pragma comment(lib, "urlmon.lib")

namespace MemoryDumper
{

    static std::unordered_set<std::string> printedSet;
    static std::mutex printMutex;

    inline bool isPrintable(char c) { return std::isprint(static_cast<unsigned char>(c)); }

    inline bool InvokeCommand(const std::string& s)
    {
        return s.find("Invoke-WebRequest") != std::string::npos ||
            s.find("Invoke-RestMethod") != std::string::npos;
    }

    inline void processBlock(const std::vector<char>& block)
    {
        std::string current;
        for (char c : block) {
            if (isPrintable(c)) current += c;
            else {
                if (!current.empty() && InvokeCommand(current)) {
                    std::lock_guard<std::mutex> lock(printMutex);
                    if (printedSet.insert(current).second) std::cout << current << "\n\n";
                }
                current.clear();
            }
        }
        if (!current.empty() && InvokeCommand(current)) {
            std::lock_guard<std::mutex> lock(printMutex);
            if (printedSet.insert(current).second) std::cout << current << "\n\n";
        }
    }

    inline bool downloadWinPmem(const std::string& url, const std::string& outputPath)
    {
        HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), outputPath.c_str(), 0, NULL);
        return SUCCEEDED(hr);
    }

    inline bool runWinPmem()
    {
        const std::string exePath = "C:\\winpmem_mini_x64_rc2.exe";
        const std::string memdumpPath = "C:\\memdump.raw";

        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = "runas";
        sei.lpFile = "cmd.exe";
        sei.lpParameters = ("/c \"" + exePath + " " + memdumpPath + "\"").c_str();
        sei.nShow = SW_SHOW;

        if (!ShellExecuteExA(&sei)) {
            std::cerr << "[-] Failed to execute WinPmem.\n";
            return false;
        }

        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
        return true;
    }

    inline void dumpMemory()
    {
        const std::string winpmemPath = "C:\\winpmem_mini_x64_rc2.exe";
        const std::string winpmemURL = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe";
        const std::string memdumpPath = "C:\\memdump.raw";

        char choice;
        std::cout << "Do you want to dump memory? (y/n): ";
        std::cin >> choice;
        if (choice != 'y' && choice != 'Y') {
            return;
        }

        if (GetFileAttributesA(winpmemPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::cout << "[*] Downloading WinPmem...\n";
            if (!downloadWinPmem(winpmemURL, winpmemPath)) {
                std::cerr << "[-] Failed to download WinPmem\n";
                return;
            }
            std::cout << "[+] Download completed: " << winpmemPath << "\n";
        }

        std::cout << "[*] Running WinPmem in visible admin cmd...\n";
        if (!runWinPmem()) {
            std::cerr << "[-] WinPmem execution failed.\n";
            return;
        }
        std::cout << "[+] WinPmem finished. Memdump created at C:\\memdump.raw\n\n";

        std::ifstream file(memdumpPath, std::ios::binary);
        if (!file) {
            std::cerr << "[-] Failed to open memdump file\n";
            return;
        }

        const size_t BLOCK_SIZE = 8 * 1024 * 1024; // 8 MB
        const unsigned int NUM_THREADS = std::thread::hardware_concurrency();
        std::vector<std::thread> workers;

        while (file) {
            std::vector<char> buffer(BLOCK_SIZE);
            file.read(buffer.data(), buffer.size());
            size_t bytesRead = file.gcount();
            if (bytesRead == 0) break;
            buffer.resize(bytesRead);

            workers.emplace_back([buffer]() mutable { processBlock(buffer); });

            if (workers.size() >= NUM_THREADS) {
                for (auto& t : workers) t.join();
                workers.clear();
            }
        }

        for (auto& t : workers) t.join();

        std::cout << "Total commands found: " << printedSet.size() << "\n";

    }
}