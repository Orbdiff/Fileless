#include <set>

#include "time_utils.hpp"
#include "eventvwr.hpp"
#include "memory_dumper.hpp"

int wmain() 
{
    time_t logonUtc = GetCurrentUserLogonTimeUTC();
    LocalTime(logonUtc);

    std::set<std::wstring> HostApps;
    int counter = 0;

    ReadHostApplicationEvents(L"Windows PowerShell", logonUtc, HostApps, counter);
    ReadHostApplicationEvents(L"Microsoft-Windows-PowerShell/Operational", logonUtc, HostApps, counter);

    MemoryDumper::dumpMemory();

    system("pause");
    return 0;
}