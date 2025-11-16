#pragma once
#include <windows.h>
#include <winevt.h>
#include <iostream>
#include <string>
#include <set>
#include <vector>
#include <algorithm>

#include "../utils/time_utils.hpp"

bool g_NoSuspiciousPrinted = false;
bool g_FoundAnySuspicious = false;

std::wstring tolower_ws(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

void ReadHostApplicationEvents(const std::wstring& channelName,
    time_t logonUtc,
    std::set<std::wstring>& HostApps,
    int& counter)
{
    EVT_HANDLE hResults = EvtQuery(NULL, channelName.c_str(), NULL,
        EvtQueryChannelPath | EvtQueryReverseDirection);

    if (!hResults) {
        std::wcerr << L"[!] Failed to open channel: " << channelName << L" (Error " << GetLastError() << L")\n";
        return;
    }

    const int batchSize = 50;
    std::vector<EVT_HANDLE> events(batchSize);
    DWORD returned = 0;

    std::vector<std::wstring> suspiciousPatterns = {
        L"invoke-", L"iex", L"invoke-expression", L"downloadstring",
        L"downloadfile", L"webclient", L"bits", L"bitstransfer",
        L"curl", L"wget", L"powershell -enc", L"frombase64string",
        L"new-object", L"start-process", L"invoke-webrequest",
        L"invoke-restmethod"
    };

    while (EvtNext(hResults, batchSize, events.data(), INFINITE, 0, &returned) && returned > 0)
    {
        for (DWORD i = 0; i < returned; i++)
        {
            DWORD bufferUsed = 0, propertyCount = 0;
            EvtRender(NULL, events[i], EvtRenderEventXml, 0, NULL, &bufferUsed, &propertyCount);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                std::wstring buffer(bufferUsed / sizeof(wchar_t), L'\0');

                if (!EvtRender(NULL, events[i], EvtRenderEventXml, bufferUsed,
                    &buffer[0], &bufferUsed, &propertyCount))
                {
                    EvtClose(events[i]);
                    continue;
                }

                time_t eventTime = ParseSystemTimeUTC(buffer);
                if (eventTime < logonUtc) {
                    EvtClose(events[i]);
                    continue;
                }

                size_t pos = buffer.find(L"HostApplication=");
                if (pos == std::wstring::npos) {
                    EvtClose(events[i]);
                    continue;
                }

                size_t end = buffer.find(L"\n", pos);
                std::wstring line = buffer.substr(pos, end - pos);

                std::wstring value;
                size_t eq = line.find(L'=');
                if (eq != std::wstring::npos)
                    value = line.substr(eq + 1);

                if (!value.empty() && value.front() == L'"') value.erase(0, 1);
                if (!value.empty() && value.back() == L'"') value.pop_back();

                std::wstring lowerValue = tolower_ws(value);

                bool isSuspicious = false;
                for (auto& pat : suspiciousPatterns)
                    if (lowerValue.find(pat) != std::wstring::npos)
                        isSuspicious = true;

                if (isSuspicious)
                {
                    if (HostApps.find(value) == HostApps.end())
                    {
                        g_FoundAnySuspicious = true;
                        counter++;

                        std::wcout << L"[#] Suspicious Command " << counter << L":\n";
                        std::wcout << value << L"\n\n";

                        HostApps.insert(value);
                    }
                }
            }

            EvtClose(events[i]);
        }
    }

    EvtClose(hResults);
}

void RunHostApplicationScan()
{
    time_t logonUtc = GetCurrentUserLogonTimeUTC();
    LocalTime(logonUtc);

    std::set<std::wstring> HostApps;
    int counter = 0;

    ReadHostApplicationEvents(L"Windows PowerShell", logonUtc, HostApps, counter);
    ReadHostApplicationEvents(L"Microsoft-Windows-PowerShell/Operational", logonUtc, HostApps, counter);

    if (!g_FoundAnySuspicious)
    {
        std::wcout << L"[!] No suspicious HostApplication commands found.\n\n";
    }
}