#include <windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <iostream>
#include <stdio.h>
#include <tlhelp32.h>
#include <taskschd.h>

#define BITNESS(bits) (sizeof(LPVOID) * 8 == (bits))

BOOL Is64BitOperatingSystem()
{
	BOOL wow64 = FALSE;
	return BITNESS(64) || IsWow64Process(GetCurrentProcess(), &wow64) && wow64;
}

VOID RemoteUnhookDLL(HANDLE hProcess, LPCWSTR name)
{
	if (name)
	{
		if (hProcess != NULL)
		{
			WCHAR path[MAX_PATH + 1];
			WCHAR windowsPath[MAX_PATH];
			GetWindowsDirectory(windowsPath, MAX_PATH);
			WCHAR driveLetter = windowsPath[0];
			WCHAR driveLetterWide[2];
			driveLetterWide[0] = driveLetter;
			driveLetterWide[1] = L'\0';
			LPCWSTR driveLetterLPCWSTR = driveLetterWide;
			StrCpyW(path, driveLetterLPCWSTR);
			if (Is64BitOperatingSystem() && BITNESS(32))
			{
				StrCatW(path, L":\\Windows\\SysWOW64\\");
			}
			else
			{
				StrCatW(path, L":\\Windows\\System32\\");
			}
			StrCatW(path, name);

			HMODULE dll = GetModuleHandleW(name);
			if (dll)
			{
				MODULEINFO moduleInfo;
				memset(&moduleInfo, 0, sizeof(MODULEINFO));

				if (GetModuleInformation(hProcess, dll, &moduleInfo, sizeof(MODULEINFO)))
				{
					HANDLE dllFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
					if (dllFile != INVALID_HANDLE_VALUE)
					{
						HANDLE dllMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
						if (dllMapping)
						{
							LPVOID dllMappedFile = MapViewOfFile(dllMapping, FILE_MAP_READ, 0, 0, 0);
							if (dllMappedFile)
							{
								PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleInfo.lpBaseOfDll + ((PIMAGE_DOS_HEADER)moduleInfo.lpBaseOfDll)->e_lfanew);

								for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
								{
									PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(ntHeaders) + (i * (ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER));

									if (!lstrcmpA((LPCSTR)sectionHeader->Name, ".text"))
									{
										LPVOID virtualAddress = (LPVOID)((ULONG_PTR)moduleInfo.lpBaseOfDll + (ULONG_PTR)sectionHeader->VirtualAddress);
										DWORD virtualSize = sectionHeader->Misc.VirtualSize;

										DWORD oldProtect;
										VirtualProtectEx(hProcess, virtualAddress, virtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
										WriteProcessMemory(hProcess, virtualAddress, (LPVOID)((ULONG_PTR)dllMappedFile + (ULONG_PTR)sectionHeader->VirtualAddress), virtualSize, NULL);
										VirtualProtectEx(hProcess, virtualAddress, virtualSize, oldProtect, &oldProtect);

										break;
									}
								}
							}
							CloseHandle(dllMapping);
						}
						CloseHandle(dllFile);
					}
				}
				FreeLibrary(dll);
			}
		}
	}
}

BOOL EnableDebugPrivilege()
{
	BOOL result = FALSE;

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	if (process)
	{
		HANDLE token;
		if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		{
			LUID luid;
			if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid))
			{
				TOKEN_PRIVILEGES tokenPrivileges;
				tokenPrivileges.PrivilegeCount = 1;
				tokenPrivileges.Privileges[0].Luid = luid;
				tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				if (AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
				{
					result = GetLastError() != ERROR_NOT_ALL_ASSIGNED;
				}
			}
		}

		CloseHandle(process);
	}

	return result;
}

BOOL DeleteScheduledTask(LPCWSTR name)
{
	BOOL result = FALSE;

	BSTR nameBstr = SysAllocString(name);
	BSTR folderPathBstr = SysAllocString(L"\\");

	if (SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
	{
		HRESULT initializeSecurityResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (SUCCEEDED(initializeSecurityResult) || initializeSecurityResult == RPC_E_TOO_LATE)
		{
			ITaskService* service = NULL;
			if (SUCCEEDED(CoCreateInstance(__uuidof(TaskScheduler), nullptr, CLSCTX_INPROC_SERVER, __uuidof(ITaskService), (void**)&service)))
			{
				VARIANT empty;
				VariantInit(&empty);

				if (SUCCEEDED(service->Connect(empty, empty, empty, empty)))
				{
					ITaskFolder* folder = NULL;
					if (SUCCEEDED(service->GetFolder(folderPathBstr, &folder)))
					{
						if (SUCCEEDED(folder->DeleteTask(nameBstr, 0)))
						{
							result = TRUE;
						}

						folder->Release();
					}
				}

				service->Release();
			}
		}

		CoUninitialize();
	}

	SysFreeString(nameBstr);
	SysFreeString(folderPathBstr);

	return result;
}

int main()
{
	Sleep(1000);
	RemoteUnhookDLL(GetCurrentProcess(), L"ntdll.dll");
	RemoteUnhookDLL(GetCurrentProcess(), L"advapi32.dll");
	RemoteUnhookDLL(GetCurrentProcess(), L"sechost.dll");
	RemoteUnhookDLL(GetCurrentProcess(), L"pdh.dll");
	RemoteUnhookDLL(GetCurrentProcess(), L"amsi.dll");
	EnableDebugPrivilege();
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hProcessSnap, &pe32);
	do
	{
		HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (wcscmp(pe32.szExeFile, L"dllhost.exe") == 0)
		{
			TerminateProcess(processHandle, 0);
		}
		else
		{
			RemoteUnhookDLL(processHandle, L"ntdll.dll");
			RemoteUnhookDLL(processHandle, L"advapi32.dll");
			RemoteUnhookDLL(processHandle, L"sechost.dll");
			RemoteUnhookDLL(processHandle, L"pdh.dll");
			RemoteUnhookDLL(processHandle, L"amsi.dll");
		}
		CloseHandle(processHandle);
	}
	while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	DeleteScheduledTask(L"$77svc64");
	DeleteScheduledTask(L"$77svc32");
	system("cls");
	printf("%s\n", "Ring3 Rootkit Unhooked!");
	system("pause");
	exit(0);
	return 0;
}
