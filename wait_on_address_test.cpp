#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <malloc.h>
#include <assert.h>
#include <float.h>
#include <intrin.h>

#include <immintrin.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Synchronization.lib")

uint32_t WaitValue = 0;
uint32_t WakerThreadWaitValue = 0u;
LARGE_INTEGER wakeStart = {};
LARGE_INTEGER wakeEnd = {};
LARGE_INTEGER frequency = {};

float minMs[2] = {FLT_MAX};
float maxMs[2] = {FLT_MIN};
float avgMs[2] = {0.0f};

#define TEST_WAKE_UP_LATENCY(func, idx) \
{                                                                                                                           \
    func;                                                                                                                   \
    QueryPerformanceCounter(&wakeEnd);                                                                                      \
    const float wakeUpTimeInMs = (float)((wakeEnd.QuadPart - wakeStart.QuadPart) * 1000.f) / (float)frequency.QuadPart;     \
    minMs[idx] = min(minMs[idx], wakeUpTimeInMs);                                                                           \
    maxMs[idx] = max(minMs[idx], wakeUpTimeInMs);                                                                           \
    avgMs[idx] += wakeUpTimeInMs;                                                                                           \
}

void UmonitorWaitOnAddress(uint32_t* __restrict pWaitValue, const uint32_t* __restrict pExpectedValue)
{
    const uint32_t expectedValue = *pExpectedValue;
    _umonitor(pWaitValue);
    do
    {
        _umwait(0, (~0ull));
        _ReadBarrier();
    } while (*pWaitValue == expectedValue);
}

void ResetWakerThread()
{
    WakerThreadWaitValue = 1;
    WakeByAddressSingle(&WakerThreadWaitValue);
}

typedef DWORD (WINAPI *PTHREAD_START_ROUTINE)(
    LPVOID lpThreadParameter
    );

DWORD WINAPI WakerThreadEntryPoint(LPVOID)
{
    uint32_t wakeValue = WakerThreadWaitValue;
    while(true)
    {
        WaitOnAddress(&WakerThreadWaitValue, &wakeValue, sizeof(wakeValue), INFINITE);
        WakerThreadWaitValue = 0;
        Sleep(1);

        QueryPerformanceCounter(&wakeStart);
        WaitValue = 1;
        WakeByAddressSingle(&WaitValue);
    }
}

int main(int argc, const char** argv)
{
    QueryPerformanceFrequency(&frequency);

    CreateThread(nullptr, 0u, WakerThreadEntryPoint, nullptr, 0u, nullptr);
    Sleep(100);
    for(uint32_t i = 0u; i < 1000; ++i)
    {
        const uint32_t bla = WaitValue;

        {
                ResetWakerThread();
                TEST_WAKE_UP_LATENCY(WaitOnAddress(&WaitValue, (PVOID)&bla, sizeof(bla), INFINITE), 0);
                WaitValue = 0;
        }

        {
                ResetWakerThread();
                TEST_WAKE_UP_LATENCY(UmonitorWaitOnAddress(&WaitValue, &bla), 1);
                assert(WaitValue == 1u);
                WaitValue = 0;
        }
    }

    avgMs[0] /= 1000.f;
    avgMs[1] /= 1000.f;

    printf("WaitOnAddress Stats:\nMin wake up time in MS: %.5f\nMax wake up time in MS: %.5f\nAvg wake up time in MS: %.5f\n\n", minMs[0], maxMs[0], avgMs[0]);
    printf("umonitor/umwait Stats:\nMin wake up time in MS: %.5f\nMax wake up time in MS: %.5f\nAvg wake up time in MS: %.5f\n\n", minMs[1], maxMs[1], avgMs[1]);
    fflush(stdout);

}