#include "utils/time_utils.hpp"
#include "events/eventvwr.hpp"
#include "memory/memory_dumper.hpp"

int wmain()
{
    RunHostApplicationScan();
    dumpMemory();
    system("pause");
    return 0;
}