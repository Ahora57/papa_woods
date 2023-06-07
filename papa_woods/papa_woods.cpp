
#include <iostream>
#include "dump_syscall.h"

int main()
{
    INT  process_platrorm = dump_syscall_util::get_proc_info::get_process_platform();
    if (process_platrorm == PROCESS_32)
        std::cout << "Process is x32(x32 system)\n";
    else if(process_platrorm == PROCESS_64)
        std::cout << "Process is x64(x64 system)\n";
    else if(process_platrorm == PROCESS_WOW64)
        std::cout << "Process is WoW64(x64 system)\n";
    else
        std::cout << "Unknown process(not supported)\n";
    
    dump_syscall_util::syscall_help_map mapped_dll;

    std::cout << std::dec << "windows build number ->\t" << NtCurrentPeb()->OSBuildNumber << '\n';
    std::cout << "syscall number NtQueryInformationProcess ->\t0x" << std::hex << mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtQueryInformationProcess") )<< '\n';
    std::cout << "syscall number NtSetInformationProcess ->\t0x" << std::hex << mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtSetInformationProcess") )<< '\n';
    std::cout << "syscall number NtDebugActiveProcess ->\t0x" << std::hex << mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtDebugActiveProcess")) << '\n';
    std::cout << "syscall number NtRemoveProcessDebug ->\t0x" << std::hex << mapped_dll.map_get_syscall(L"ntdll.dll", FNV("NtRemoveProcessDebug")) << '\n';
     
    std::cin.get();

    return NULL;
}


