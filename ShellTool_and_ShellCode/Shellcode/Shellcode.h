#pragma once
#include <Windows.h>
#include <compressapi.h>


HMODULE GetKernel32();
HMODULE GetModuleBase();
FARPROC MyGetProcAddress(HMODULE hMod, LPCSTR lpProcName);

void* __cdecl memcpy(
	void* dst,
	const void* src,
	size_t count
);

typedef FARPROC(WINAPI* PFN_GetProcAddress)(
	HMODULE hModule,
	LPCSTR lpProcName
	);

typedef HMODULE(WINAPI* PFN_LoadLibraryA)(
	LPCSTR lpLibFileName
	);

typedef BOOL(WINAPI* PFN_CreateDecompressor)(
	DWORD Algorithm,
	PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
	PDECOMPRESSOR_HANDLE DecompressorHandle
	);

typedef BOOL(WINAPI* PFN_Decompress)(
	DECOMPRESSOR_HANDLE DecompressorHandle,
	LPCVOID CompressedData,
	SIZE_T	CompressedDataSize,
	PVOID	UncompressedBuffer,
	SIZE_T	UncompressedBufferSize,
	PSIZE_T	UncompressedDataSize
	);
typedef
LPVOID (WINAPI* PFN_VirtualAlloc)(LPVOID lpAddress, DWORD dwSize,
	DWORD flAllocationType, DWORD flProtect);

typedef
BOOL(WINAPI* PFN_VirtualProtect)(LPVOID lpAddress, DWORD dwSize, DWORD flNewProtect,
	PDWORD lpflOldProtect);

struct Environment {

	PFN_GetProcAddress pfnGetProcAddress;
	PFN_LoadLibraryA pfnLoadLibraryA;
	PFN_CreateDecompressor pfnCreateDecompressor;
	PFN_Decompress pfnDecompress;
	PFN_VirtualAlloc pfnVirtualAlloc;
	PFN_VirtualProtect pfnVirtualProtect;
};

void InitEnvironment(Environment* pEnv);