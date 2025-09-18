#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include <ctime>
#include <iostream>
#include <iomanip>

#pragma comment(lib, "Secur32.lib")

inline time_t FileTimeToTimeT(const FILETIME& ft)
{
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    return static_cast<time_t>((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

inline time_t GetCurrentUserLogonTimeUTC()
{
    wchar_t username[256]; DWORD size = sizeof(username) / sizeof(wchar_t);
    if (!GetUserNameW(username, &size)) return 0;

    ULONG count = 0; PLUID sessions = nullptr;
    if (LsaEnumerateLogonSessions(&count, &sessions) != 0) return 0;

    time_t result = 0;
    for (ULONG i = 0; i < count; i++) {
        PSECURITY_LOGON_SESSION_DATA pData = nullptr;
        if (LsaGetLogonSessionData(&sessions[i], &pData) == 0 && pData) {
            if (pData->UserName.Buffer && pData->LogonType == 2 &&
                _wcsicmp(pData->UserName.Buffer, username) == 0) {

                FILETIME ft{ pData->LogonTime.LowPart, pData->LogonTime.HighPart };
                result = FileTimeToTimeT(ft);
                LsaFreeReturnBuffer(pData);
                break;
            }
            LsaFreeReturnBuffer(pData);
        }
    }
    if (sessions) LsaFreeReturnBuffer(sessions);
    return result;
}

inline void LocalTime(time_t t)
{
    if (t == 0) return;
    struct tm timeinfo;
    localtime_s(&timeinfo, &t);
    std::cout << "[+] LogonTime: " << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S\n") << "[!] Only search for events after the logon time ^" << "\n\n";
}

inline time_t ParseSystemTimeUTC(const std::wstring& xml)
{
    size_t pos = xml.find(L"SystemTime='");
    if (pos == std::wstring::npos) return 0;
    pos += wcslen(L"SystemTime='");
    std::wstring utcStr = xml.substr(pos, 19);

    tm tmEvent{};
    swscanf_s(utcStr.c_str(), L"%4d-%2d-%2dT%2d:%2d-%2d",
        &tmEvent.tm_year, &tmEvent.tm_mon, &tmEvent.tm_mday,
        &tmEvent.tm_hour, &tmEvent.tm_min, &tmEvent.tm_sec);
    tmEvent.tm_year -= 1900;
    tmEvent.tm_mon -= 1;

    return _mkgmtime(&tmEvent);
}