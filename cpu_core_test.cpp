#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>

#define ADVANCE_TO_NEXT_PROCESSOR_INFORMATION(pLpiEx) (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)((char*)pLpiEx + pLpiEx->Size)

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdint.h>
#include <stdio.h>
#include <malloc.h>

#include "win32_helper.hpp"

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ws2_32.lib")

uint8_t unpatchedGetProcessorInformationExBytes[13] = {};
uint8_t unpatchedGetProcessorInformationBytes[13] = {};
proc_spoofer_win32_entry_t spoofEntry = {};

bool patchFunction(HMODULE pModule, const char* pFunctionName, const void* pPatchedFunctionPtr, uint8_t* pOutUnpatchedFunctionBytes);
bool unpatchFunction(HMODULE pModule, const char* pFunctionName, const uint8_t* pUnpatchedByteBuffer);

typedef HMODULE(*LoadLibraryAProc)(LPCSTR);
typedef HMODULE(*LoadLibraryWProc)(LPCWSTR);

BOOL WINAPI patchedGetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer, PDWORD ReturnedLength)
{
    const bool spoofOutput = (RelationshipType == RelationAll || RelationshipType == RelationProcessorCore);
    HMODULE pKernel32Lib = GetModuleHandleA("Kernel32.dll");

    if(!spoofOutput || Buffer == nullptr || ReturnedLength == nullptr)
    {
        unpatchFunction(pKernel32Lib, "GetLogicalProcessorInformationEx", unpatchedGetProcessorInformationExBytes);
        const BOOL returnValue = GetLogicalProcessorInformationEx(RelationshipType, Buffer, ReturnedLength);
        patchFunction(pKernel32Lib, "GetLogicalProcessorInformationEx", patchedGetLogicalProcessorInformationEx, nullptr);
        return returnValue;
    }

    unpatchFunction(pKernel32Lib, "GetLogicalProcessorInformationEx", unpatchedGetProcessorInformationExBytes);
    const BOOL returnValue = GetLogicalProcessorInformationEx(RelationshipType, Buffer, ReturnedLength);
    patchFunction(pKernel32Lib, "GetLogicalProcessorInformationEx", patchedGetLogicalProcessorInformationEx, nullptr);

    DWORD logicalProcessorInformationSizeInBytes = *ReturnedLength;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX pProcessorInformation = Buffer;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX pSpoofedProcessorInformation = spoofEntry.pHostProcessorInformation;

    uint32_t processorIndex = 0u;
    while(true)
    {
        if(logicalProcessorInformationSizeInBytes == 0)
        {
            break;
        }
        logicalProcessorInformationSizeInBytes -= pProcessorInformation->Size;

        if(pProcessorInformation->Relationship == RelationProcessorCore)
        {
            if(spoofEntry.processorEnableMask & (1ull << processorIndex))
            {
                memcpy(pProcessorInformation, pSpoofedProcessorInformation, pProcessorInformation->Size);
                pProcessorInformation = ADVANCE_TO_NEXT_PROCESSOR_INFORMATION(pProcessorInformation);
            }
            else
            {
                memmove(pProcessorInformation, (char*)pProcessorInformation + pProcessorInformation->Size, logicalProcessorInformationSizeInBytes);
                *ReturnedLength -= pProcessorInformation->Size;
            }

            ++processorIndex;
            pSpoofedProcessorInformation = ADVANCE_TO_NEXT_PROCESSOR_INFORMATION(pSpoofedProcessorInformation);
        }
        else
        {
            pProcessorInformation = ADVANCE_TO_NEXT_PROCESSOR_INFORMATION(pProcessorInformation);
        }

    }
    
    return TRUE;
}

BOOL WINAPI patchedGetLogicalProcessorInformation(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION Buffer, PDWORD ReturnedLength)
{
    return FALSE;
}

bool unpatchFunction(HMODULE pModule, const char* pFunctionName, const uint8_t* pUnpatchedByteBuffer)
{
    LPCVOID pFunctionBaseAddress = WIN32_CALL_CHECK(GetProcAddress(pModule, pFunctionName));
    if(pFunctionBaseAddress == nullptr)
    {
        return false;
    }

    if(FALSE == WIN32_CALL_CHECK(WriteProcessMemory(GetCurrentProcess(), (void*)pFunctionBaseAddress, pUnpatchedByteBuffer, 13, nullptr)))
    {
        return false;
    }

    return true;
}

bool patchFunction(HMODULE pModule, const char* pFunctionName, const void* pPatchedFunctionPtr, uint8_t* pOutUnpatchedFunctionBytes)
{
    LPCVOID pFunctionBaseAddress = WIN32_CALL_CHECK(GetProcAddress(pModule, pFunctionName));
    if(pFunctionBaseAddress == nullptr)
    {
        return false;
    }

    uint8_t functionStartBytes[13] = {};
    if(FALSE == WIN32_CALL_CHECK(ReadProcessMemory(GetCurrentProcess(), pFunctionBaseAddress, functionStartBytes, sizeof(functionStartBytes), nullptr)))
    {
        return false;
    }

    if(pOutUnpatchedFunctionBytes != nullptr)
    {
        memcpy(pOutUnpatchedFunctionBytes, functionStartBytes, sizeof(functionStartBytes));
    }

    //FK: This is basically
    //    mov r11, 0x0000000000000000
    //    push r11
    //    ret
    //
    //    0x0000000000000000 will be replaced by the address of the patched function in the memcpy
    uint8_t patchedStartBytes[13] = {u'\x48', u'\xB8', 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, u'\x50', u'\x48', u'\xC3'};
    static_assert(sizeof(functionStartBytes) == sizeof(patchedStartBytes));

    memcpy(patchedStartBytes + 2u, &pPatchedFunctionPtr, 8u);

    if(FALSE == WIN32_CALL_CHECK(WriteProcessMemory(GetCurrentProcess(), (void*)pFunctionBaseAddress, patchedStartBytes, sizeof(patchedStartBytes), nullptr)))
    {
        return false;
    }

    return true;
}

void tryToPatchFunction(SOCKET clientSocket, HMODULE pModule, const char* pFunctionName, const void* pPatchedFunctionPtr, uint8_t* pOutUnpatchedFunctionBytes)
{
    patchFunction(pModule, pFunctionName, pPatchedFunctionPtr, pOutUnpatchedFunctionBytes);

}

void patchProcessorInformationFunctions(SOCKET clientSocket)
{
    HMODULE pKernel32Module = GetModuleHandleA("Kernel32.dll");

    //tryToPatchFunction(clientSocket, pKernel32Module, "GetLogicalProcessorInformationEx", &patchedGetLogicalProcessorInformationEx, unpatchedGetProcessorInformationExBytes);
    tryToPatchFunction(clientSocket, pKernel32Module, "GetLogicalProcessorInformationEx", &patchedGetLogicalProcessorInformationEx, unpatchedGetProcessorInformationExBytes);
    //tryToPatchFunction(clientSocket, pKernel32Module, "GetLogicalProcessorInformation", &patchedGetLogicalProcessorInformation, unpatchedGetProcessorInformationBytes);
}

bool tryToReadFlagsFromRegistry(SOCKET clientSocket, uint16_t* pOutFlags)
{
    bool success = false;
    HKEY pDeaffinitizerRegistryKey = nullptr;
    HKEY pExecutableRegistryKey = nullptr;
    char executableFilePath[MAX_PATH] = {};
    char executableFileName[MAX_PATH] = {};
    uint16_t flags = 0u;
    DWORD flagsSizeInBytes = sizeof(flags);

    WIN32_CALL_CHECK(GetModuleFileNameA(nullptr, executableFilePath, sizeof(executableFilePath)));
    extractExecutableFileNameFromPath(executableFilePath, executableFileName);

    if(ERROR_SUCCESS != WIN32_CALL_CHECK_RESULT(RegCreateKeyExA(HKEY_CURRENT_USER, pRegistryPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ, nullptr, &pDeaffinitizerRegistryKey, nullptr)))
    {
        return false;
    }

    if(ERROR_SUCCESS != WIN32_CALL_CHECK_RESULT(RegOpenKeyExA(pDeaffinitizerRegistryKey, executableFileName, 0, KEY_READ, &pExecutableRegistryKey)))
    {
        goto cleanup_and_exit;
    }

    if(ERROR_SUCCESS != WIN32_CALL_CHECK_RESULT(RegGetValueA(pExecutableRegistryKey, nullptr, "Flags", RRF_RT_REG_BINARY, nullptr, (LPVOID)&flags, &flagsSizeInBytes)))
    {
        goto cleanup_and_exit;
    }

    success = true;
    *pOutFlags = flags;

cleanup_and_exit:
    RegCloseKey(pExecutableRegistryKey);
    RegCloseKey(pDeaffinitizerRegistryKey);

    return success;
}

bool tryToLoadSpoofingProcessorInformationFromRegistry(proc_spoofer_win32_entry_t* pEntry)
{
    char executabeFilePath[MAX_PATH] = {};
    char executableFileName[MAX_PATH] = {};

    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* pLogicalProcessorInformation = nullptr;
    uint32_t logicalProcessorInformationSize = 0u;
    if(!tryToQueryCurrentProcessorInformation(&pLogicalProcessorInformation, &logicalProcessorInformationSize))
    {
        return false;
    }

    pEntry->pHostProcessorInformation = pLogicalProcessorInformation;
    pEntry->hostProcessorInformationSizeInBytes = logicalProcessorInformationSize;

    GetModuleFileNameA(nullptr, executabeFilePath, MAX_PATH);
    extractExecutableFileNameFromPath(executabeFilePath, executableFileName);

    if(!tryToLoadEntryFromRegistry(executableFileName, pEntry))
    {
        return false;
    }

    return true;
}

typedef UINT		(WINAPI *PFNNTDELAYEXECUTIONPROC)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
PFNNTDELAYEXECUTIONPROC		w32NtDelayExecution		= (PFNNTDELAYEXECUTIONPROC)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtDelayExecution" );

void MySleep(int dwMilliseconds)
{
    LARGE_INTEGER sleepTimeIn100sNs;
    sleepTimeIn100sNs.QuadPart = (-10000);
    w32NtDelayExecution(FALSE, &sleepTimeIn100sNs);
}

int main(int argc, const char** argv)
{
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);

    for(int i = 0; i < 1000; ++i)
    {
        QueryPerformanceCounter(&start);
        MySleep(1);
        //Sleep(1);
        QueryPerformanceCounter(&end);
        const float timeInMs = (float)(end.QuadPart - start.QuadPart) * 1000.f / (float)frequency.QuadPart;
        printf("Sleep(1) = %.3fms\n", timeInMs);
    }

    return 0;
}