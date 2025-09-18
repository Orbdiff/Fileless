#pragma once

#include <windows.h>
#include <winevt.h>
#include <iostream>
#include <string>
#include <set>

#include "time_utils.hpp"

#pragma comment(lib, "wevtapi.lib")

inline void ReadHostApplicationEvents(const std::wstring& channelName, time_t logonUtc, std::set<std::wstring>& HostApps, int& counter)
{
    EVT_HANDLE hResults = EvtQuery(NULL, channelName.c_str(), NULL, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hResults) { std::wcerr << L"[!] Failed to open channel (event): " << channelName << L" (" << GetLastError() << L")\n"; return; }

    const int batchSize = 50;
    EVT_HANDLE* events = new EVT_HANDLE[batchSize];
    DWORD returned = 0;

    while (EvtNext(hResults, batchSize, events, INFINITE, 0, &returned) && returned > 0) {
        for (DWORD i = 0; i < returned; i++) {
            DWORD bufferUsed = 0, propertyCount = 0;
            EvtRender(NULL, events[i], EvtRenderEventXml, 0, NULL, &bufferUsed, &propertyCount);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::wstring buffer(bufferUsed / sizeof(wchar_t), L'\0');
                if (EvtRender(NULL, events[i], EvtRenderEventXml, bufferUsed, &buffer[0], &bufferUsed, &propertyCount)) {
                    time_t eventTime = ParseSystemTimeUTC(buffer);
                    if (eventTime >= logonUtc) {
                        size_t pos = buffer.find(L"HostApplication=");
                        if (pos != std::wstring::npos) {
                            size_t end = buffer.find(L"\n", pos);
                            std::wstring hostAppLine = buffer.substr(pos, end - pos);

                            if (hostAppLine.find(L"Invoke-") != std::wstring::npos) {
                                size_t equalPos = hostAppLine.find(L'=');
                                if (equalPos != std::wstring::npos && equalPos + 1 < hostAppLine.size()) {
                                    std::wstring hostAppValue = hostAppLine.substr(equalPos + 1);
                                    if (HostApps.find(hostAppValue) == HostApps.end()) {
                                        counter++;
                                        std::wcout << L"[#] Filess Command " << counter << L":\n";
                                        std::wcout << hostAppValue << L"\n\n";
                                        HostApps.insert(hostAppValue);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            EvtClose(events[i]);
        }
    }

    delete[] events;
    EvtClose(hResults);
}