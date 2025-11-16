#pragma once
#include <windows.h>
#include <ntsecapi.h>
#include <ctime>
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>

time_t FileTimeToTimeT(const FILETIME& ft)
{
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    constexpr unsigned long long EPOCH_DIFF = 116444736000000000ULL;

    if (ull.QuadPart < EPOCH_DIFF) return 0;
    return static_cast<time_t>((ull.QuadPart - EPOCH_DIFF) / 10000000ULL);
}

time_t GetCurrentUserLogonTimeUTC()
{
    wchar_t username[256];
    DWORD size = 256;
    if (!GetUserNameW(username, &size))
        return 0;

    ULONG count = 0;
    PLUID sessions = nullptr;

    if (LsaEnumerateLogonSessions(&count, &sessions) != 0)
        return 0;

    time_t bestLogon = 0;

    for (ULONG i = 0; i < count; i++)
    {
        PSECURITY_LOGON_SESSION_DATA pData = nullptr;
        if (LsaGetLogonSessionData(&sessions[i], &pData) == 0 && pData)
        {
            if (pData->UserName.Buffer &&
                pData->LogonType == 2 &&
                _wcsicmp(pData->UserName.Buffer, username) == 0)
            {
                FILETIME ft;
                ft.dwLowDateTime = static_cast<DWORD>(pData->LogonTime.LowPart);
                ft.dwHighDateTime = static_cast<DWORD>(pData->LogonTime.HighPart);

                time_t ts = FileTimeToTimeT(ft);

                if (ts > bestLogon)
                    bestLogon = ts;
            }

            LsaFreeReturnBuffer(pData);
        }
    }

    if (sessions)
        LsaFreeReturnBuffer(sessions);

    return bestLogon;
}

void LocalTime(time_t t)
{
    if (t == 0) return;

    struct tm info {};
    localtime_s(&info, &t);

    std::ostringstream ss;
    ss << "[+] LogonTime: " << std::put_time(&info, "%Y-%m-%d %H:%M:%S") << "\n[!] Only search for events after the logon time.\n\n";

    std::cout << ss.str();
}

time_t ParseSystemTimeUTC(const std::wstring& xml)
{
    const std::wstring key = L"SystemTime='";
    size_t pos = xml.find(key);
    if (pos == std::wstring::npos)
        return 0;

    pos += key.size();

    if (pos + 19 > xml.size())
        return 0;

    std::wstring utc = xml.substr(pos, 19);

    tm t{};
    if (swscanf_s(utc.c_str(), L"%4d-%2d-%2dT%2d:%2d:%2d",
        &t.tm_year, &t.tm_mon, &t.tm_mday,
        &t.tm_hour, &t.tm_min, &t.tm_sec) != 6)
        return 0;

    t.tm_year -= 1900;
    t.tm_mon -= 1;

    return _mkgmtime(&t);
}