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
#include <algorithm>

std::unordered_set<std::string> printedSet;
std::mutex printMutex;

bool isPrintable(char c) {
    return std::isprint(static_cast<unsigned char>(c));
}

std::string toLowerCopy(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return r;
}

bool InvokeCommand(const std::string& s) {
    std::string low = toLowerCopy(s);

    static const std::vector<std::string> suspicious = {
        "invoke-", "invoke ", "iex",
        "curl", "wget", "bits", "bitstransfer",
        "webclient", "downloadstring", "downloadfile",
        "invoke-webrequest", "invoke-restmethod",
        "new-object", "start-process"
    };

    size_t posHttp = low.find("http://");
    size_t posHttps = low.find("https://");
    size_t posPs1 = low.find(".ps1");

    bool hasURL = (posHttp != std::string::npos || posHttps != std::string::npos);
    bool hasPs1 = (posPs1 != std::string::npos);

    if (!hasURL && !hasPs1)
        return false;

    for (const auto& kw : suspicious) {

        size_t posKW = low.find(kw);
        if (posKW == std::string::npos)
            continue;

        bool validURL = false;
        bool validPS1 = false;

        if (hasURL) {
            size_t urlPos = (posHttp != std::string::npos ? posHttp : posHttps);
            if (posKW < urlPos)
                validURL = true;
        }

        if (hasPs1 && posKW < posPs1)
            validPS1 = true;

        if (validURL || validPS1)
            return true;
    }

    return false;
}

void processBlock(const std::vector<char>& block) {
    std::string current;
    current.reserve(1024);

    for (char c : block) {
        if (isPrintable(c))
            current += c;
        else {
            if (!current.empty() && InvokeCommand(current)) {
                std::lock_guard<std::mutex> lock(printMutex);
                if (printedSet.insert(current).second)
                    std::cout << current << "\n\n";
            }
            current.clear();
        }
    }

    if (!current.empty() && InvokeCommand(current)) {
        std::lock_guard<std::mutex> lock(printMutex);
        if (printedSet.insert(current).second)
            std::cout << current << "\n\n";
    }
}

bool downloadWinPmem(const std::string& url, const std::string& outputPath) {
    HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), outputPath.c_str(), 0, NULL);
    return SUCCEEDED(hr);
}

bool runWinPmem() {
    const std::string exePath = "C:\\winpmem_mini_x64_rc2.exe";
    const std::string memdumpPath = "C:\\memdump.raw";

    SHELLEXECUTEINFOA sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = "cmd.exe";

    std::string params = "/c \"" + exePath + " " + memdumpPath + "\"";
    sei.lpParameters = params.c_str();
    sei.nShow = SW_SHOW;

    if (!ShellExecuteExA(&sei)) {
        std::cerr << "[-] Failed to execute WinPmem.\n";
        return false;
    }

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
    }

    return true;
}

void dumpMemory() {
    const std::string winpmemPath = "C:\\winpmem_mini_x64_rc2.exe";
    const std::string winpmemURL = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe";

    const std::string memdumpPath = "C:\\memdump.raw";

    char choice;
    std::cout << "-----------------------------\n[!] Everything shown with a memory dump could be just for view in screen, doesn't confirm execution.\nDo you want to dump memory? (y/n): ";
    std::cin >> choice;
    if (choice != 'y' && choice != 'Y')
        return;

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

    const size_t BLOCK_SIZE = 8 * 1024 * 1024;
    unsigned int numThreads = std::min(4u, std::thread::hardware_concurrency());
    if (numThreads == 0) numThreads = 1;

    std::vector<std::thread> workers;

    while (file) {
        std::vector<char> buffer(BLOCK_SIZE);
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));

        size_t bytesRead = static_cast<size_t>(file.gcount());
        if (bytesRead == 0)
            break;

        buffer.resize(bytesRead);

        workers.emplace_back([buffer]() mutable {
            processBlock(buffer);
            });

        if (workers.size() >= numThreads) {
            for (auto& t : workers) t.join();
            workers.clear();
        }
    }

    for (auto& t : workers) t.join();

    std::cout << "Total commands found: " << printedSet.size() << "\n";
}