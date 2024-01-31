// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "SDK/include/Plugin.h"

void OnDllAttach()
{
	CryInitializePluginProc()();

	CryProcessPluginEventProc()(CRYPLUGINEVENT_DEBUGGER_ATTACHED, nullptr);

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

#ifndef _WIN64
	void* pPeb = (void*)__readfsdword(0x30);
	*(PDWORD)((PBYTE)pPeb + 0x68) = 0;
#else
	void* pPeb = (void*)__readgsqword(0x60);
	*(PDWORD)((PBYTE)pPeb + 0xBC) = 0;
#endif // _WIN64

#ifndef _WIN64
	//PPEB pPeb = (PPEB)__readfsdword(0x30);
	PVOID pHeapBase = !IsWow64Process(OpenProcess(0, FALSE, GetProcessId(nullptr)), nullptr)
		? (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x18))
		: (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x1030));
	DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
		? 0x40
		: 0x0C;
	DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
		? 0x44
		: 0x10;
#else
	//void* pPeb = (void*)__readgsqword(0x60);
	PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x30));
	DWORD dwHeapFlagsOffset = IsWindowsVistaOrGreater()
		? 0x70
		: 0x14;
	DWORD dwHeapForceFlagsOffset = IsWindowsVistaOrGreater()
		? 0x74
		: 0x18;
#endif // _WIN64

	* (PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset) = HEAP_GROWABLE;
	*(PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset) = 0;

#ifndef _WIN64
	SIZE_T nBytesToPatch = 12;
#else
	SIZE_T nBytesToPatch = 20;
#endif // _WIN64

	PROCESS_HEAP_ENTRY HeapEntry = { 0 };
	do
	{
		if (!HeapWalk(GetProcessHeap(), &HeapEntry))
			continue;
	} while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

	SIZE_T nDwordsToPatch = nBytesToPatch / sizeof(DWORD);
	PVOID pHeapEnd = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
	for (SIZE_T offset = 0; offset < nDwordsToPatch; offset++)
		*((PDWORD)pHeapEnd + offset) = 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)OnDllAttach, nullptr, 0, nullptr);

	return TRUE;
}

