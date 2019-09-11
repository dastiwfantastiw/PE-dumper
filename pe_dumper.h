#pragma once

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <typeinfo>

template<typename Var_type>
BOOL dump(Var_type Process);

template<typename Var_type>
BOOL GetProcessEntry(Var_type Arg, PROCESSENTRY32 &Struct);

template<typename Var_type>
BOOL GetModuleEntry(Var_type Arg, MODULEENTRY32 &Struct);

template<typename Var_type>
BOOL GetProcessEntry(Var_type Arg, PROCESSENTRY32 &Struct)
{
	HANDLE hSnapShot = 0;
	if ((typeid(Arg) == typeid(DWORD)))
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, (DWORD)Arg);
	else
		if ((typeid(Arg) == typeid(WCHAR*)))
			hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		print_error("CreateToolhelp32Snapshot");
		return 0;
	}

	Struct.dwSize = sizeof(PROCESSENTRY32);

	Process32First(hSnapShot, &Struct);
	Process32Next(hSnapShot, &Struct);

	if ((typeid(Arg) == typeid(DWORD)))
	{
		do
		{
			if (((DWORD)Arg == Struct.th32ProcessID))
			{
				CloseHandle(hSnapShot);
				return 1;
			}
		} while (Process32Next(hSnapShot, &Struct));
	}
	else
		if ((typeid(Arg) == typeid(WCHAR*)))
		{
			do
			{
				if (!lstrcmpW(Struct.szExeFile, (WCHAR*)Arg))
				{
					CloseHandle(hSnapShot);
					return 1;
				}
			} while (Process32Next(hSnapShot, &Struct));
		}

	ZeroMemory(&Struct, sizeof(Struct));

	CloseHandle(hSnapShot);
	return 0;
}

template<typename Var_type>
BOOL GetModuleEntry(Var_type Arg, MODULEENTRY32 &Struct)
{
	HANDLE hSnapShot = 0;

	PROCESSENTRY32 Temp;
	ZeroMemory(&Temp, sizeof(PROCESSENTRY32));

	if ((typeid(Arg) == typeid(DWORD)))
	{
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, (DWORD)Arg);
		GetProcessEntry<DWORD>((DWORD)Arg, Temp);
	}
	else
	{
		if (!GetProcessEntry<WCHAR*>((WCHAR*)Arg, Temp))
			return 0;
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, Temp.th32ProcessID);
	}

	Struct.dwSize = sizeof(MODULEENTRY32);

	Module32First(hSnapShot, &Struct);

	if ((typeid(Arg) == typeid(WCHAR*)))
	{
		do
		{
			if (!lstrcmpW(Struct.szModule, Temp.szExeFile))
			{
				CloseHandle(hSnapShot);
				return 1;
			}
		} while (Module32Next(hSnapShot, &Struct));
	}
	else
		if ((typeid(Arg) == typeid(DWORD)))
		{
			do
			{
				if (((DWORD)Arg == Struct.th32ProcessID))
				{
					CloseHandle(hSnapShot);
					return 1;
				}
			} while (Module32Next(hSnapShot, &Struct));
		}

	ZeroMemory(&Struct, sizeof(Struct));

	CloseHandle(hSnapShot);
	return 0;
}

template<typename Var_type>
BOOL dump(Var_type Process)
{
	PROCESSENTRY32 ProcEntry = { 0 };
	MODULEENTRY32 ModEntry = { 0 };

	GetProcessEntry<WCHAR*>(Process, ProcEntry);
	GetModuleEntry<WCHAR*>(ProcEntry.szExeFile, ModEntry);

	if (ModEntry.modBaseAddr == 0)
	{
		printf("[-] Probably x64-bit process or incorrect processname.\n");
		return 0;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcEntry.th32ProcessID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		print_error("OpenProcess");
		CloseHandle(hProcess);
		return 0;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)malloc(sizeof(IMAGE_DOS_HEADER));

	DWORD Protection = 0;
	DWORD Red = 0;

	VirtualProtectEx(hProcess, ModEntry.modBaseAddr, sizeof(IMAGE_DOS_HEADER), PAGE_READONLY, &Protection);
	ReadProcessMemory(hProcess, ModEntry.modBaseAddr, pDosHeader, sizeof(IMAGE_DOS_HEADER), &Red);
	VirtualProtectEx(hProcess, ModEntry.modBaseAddr, sizeof(IMAGE_DOS_HEADER), Protection, &Protection);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Invalid DOS signature.\n");
		CloseHandle(hProcess);

		free(pDosHeader);
		return 0;
	}
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)malloc(sizeof(IMAGE_NT_HEADERS));

	VirtualProtectEx(hProcess, (PIMAGE_NT_HEADERS)((DWORD)ModEntry.modBaseAddr + (DWORD)pDosHeader->e_lfanew), sizeof(IMAGE_NT_HEADERS), PAGE_READONLY, &Protection);
	ReadProcessMemory(hProcess, (PIMAGE_NT_HEADERS)((DWORD)ModEntry.modBaseAddr + (DWORD)pDosHeader->e_lfanew), pNtHeader, sizeof(IMAGE_NT_HEADERS), &Red);
	VirtualProtectEx(hProcess, (PIMAGE_NT_HEADERS)((DWORD)ModEntry.modBaseAddr + (DWORD)pDosHeader->e_lfanew), sizeof(IMAGE_NT_HEADERS), Protection, &Protection);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[-] Invalid NT signature.\n");
		CloseHandle(hProcess);

		free(pDosHeader);
		free(pNtHeader);
		return 0;
	}

	printf("[+] SizeOfImage = 0x%X\n", pNtHeader->OptionalHeader.SizeOfImage);

	HANDLE hFile = CreateFile(lstrcatW(ModEntry.szExePath, L"_dmp"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		print_error("CreateFile");
		CloseHandle(hProcess);
		CloseHandle(hFile);

		free(pDosHeader);
		free(pNtHeader);
		return 0;
	}

	VOID* Image = malloc(pNtHeader->OptionalHeader.SizeOfImage);

	VirtualProtectEx(hProcess, ModEntry.modBaseAddr, pNtHeader->OptionalHeader.SizeOfImage, PAGE_READONLY, &Protection);
	ReadProcessMemory(hProcess, ModEntry.modBaseAddr, (CHAR*)Image, pNtHeader->OptionalHeader.SizeOfImage * sizeof(CHAR), &Red);
	VirtualProtectEx(hProcess, ModEntry.modBaseAddr, pNtHeader->OptionalHeader.SizeOfImage, Protection, &Protection);

	DWORD Written = 0;

	if (WriteFile(hFile, (CHAR*)Image, pNtHeader->OptionalHeader.SizeOfImage, &Written, 0) == 0)
		print_error("WriteFile");

	WCHAR* FullPath = (WCHAR*)malloc(MAX_PATH * sizeof(WCHAR));

	if (GetFullPathName(ModEntry.szExePath, (MAX_PATH * sizeof(WCHAR)), FullPath, 0) == 0)
		print_error("GetFullPathName");

	wprintf(L"[+] The file has been saved to %s\n", FullPath);

	
	CloseHandle(hFile);
	CloseHandle(hProcess);
	return 1;
}
