#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <map>
#include <Windows.h>
#include <TlHelp32.h>

DWORD GetProcPID(std::string szProc)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(ProcEntry);

	DWORD dwReturned = -1;

	Process32First(hSnapshot, &ProcEntry);

	do
	{

		if (!strcmp(ProcEntry.szExeFile, szProc.c_str()))
		{
			dwReturned = ProcEntry.th32ProcessID;
		}

	} while (Process32Next(hSnapshot, &ProcEntry));

	CloseHandle(hSnapshot);
	return dwReturned;
}

typedef HMODULE(__stdcall* fnLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* fnGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(__stdcall* fnDllMain)(HMODULE, DWORD, LPVOID);

struct Loader
{
	fnGetProcAddress pGetProcAddress;
	fnLoadLibraryA pLoadLibrary;
};

void __stdcall Shellcode(Loader* p)
{
	fnLoadLibraryA pLoadLibrary = p->pLoadLibrary;
	fnGetProcAddress pGetProcAddress = p->pGetProcAddress;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)p;

	uint8_t* pBase = (uint8_t*)p;

	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS(pBase + pDosHeader->e_lfanew);

	fnDllMain pDllMain = fnDllMain((DWORD)pBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);

	DWORD delta = DWORD(pBase - pNTHeader->OptionalHeader.ImageBase);

	PIMAGE_BASE_RELOCATION pIBR = PIMAGE_BASE_RELOCATION(pBase + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	// fix relocations
	while (pIBR->VirtualAddress)
	{
		int iEntries = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		WORD* wTypeOffset = (PWORD)(pIBR + 1);

		for (int i = 0; i < iEntries; i++)
		{
			if (wTypeOffset[i])
			{
				DWORD* ptr = (DWORD*)(pBase + (pIBR->VirtualAddress + (wTypeOffset[i] & 0xFFF)));	// zero high 4 bits(type)
				*ptr += delta;
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}
	PIMAGE_IMPORT_DESCRIPTOR pImageImport = PIMAGE_IMPORT_DESCRIPTOR(pBase + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImageImport->Name)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pBase + pImageImport->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pBase + pImageImport->FirstThunk);

		HMODULE hModule = pLoadLibrary((LPCSTR)pBase + pImageImport->Name);

		if (!hModule)
		{
			return;
		}

		while (OrigFirstThunk->u1.AddressOfData)
		{
			
			if (IMAGE_SNAP_BY_ORDINAL(OrigFirstThunk->u1.Ordinal))
			{
				// Import by ordinal
				DWORD pFunction = (DWORD)pGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!pFunction)
				{
					return;
				}

				FirstThunk->u1.Function = pFunction;
			}
			else
			{
				// RVA PIMAGE_IMPORT_BY_NAME
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pBase + OrigFirstThunk->u1.AddressOfData);
				DWORD pFunction = (DWORD)pGetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!pFunction)
				{
					return;
				}

				FirstThunk->u1.Function = pFunction;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pImageImport++;
	}
	if (pNTHeader->OptionalHeader.AddressOfEntryPoint)
	{
		pDllMain((HMODULE)pBase, DLL_PROCESS_ATTACH, NULL);
	}
	return;
}

void __stdcall _size()
{
	return;
}


int main(int argc, char** argv)
{
	std::ifstream settings("settings.cfg", std::ios::in);
	freopen("logs.log", "w", stdout);
	if (!settings.is_open())
	{
		std::cout << "Cannot find settings.cfg, exiting..." << std::endl;
		return 0;
	}
	std::string szSettings[2];
	std::map<std::string, std::string> Settings;

	// parse settings
	for (int i = 0; i < 2; i++)
	{
		std::getline(settings, szSettings[i]);
		szSettings[i].erase(std::remove_if(szSettings[i].begin(), szSettings[i].end(), isspace));

		for (auto it = szSettings[i].begin(); it != szSettings[i].end(); ++it)
		{
			if (*it == '=')
			{
				std::string param(szSettings[i].begin(), it);
				it++;
				Settings[param] = std::string(it, szSettings[i].end());
				std::cout << param << " = " << Settings[param] << std::endl;
			}
		}
	}

	std::string szFileName(Settings["library"]);
	std::ifstream file(szFileName, std::ios::binary | std::ios::ate);	// std::ios::ate set pointer at the end of stream
	if (!file.is_open())
	{
		std::cout << "Cannot open file, exiting..." << std::endl;
		return 0;
	}
	std::cout << "DLL opened" << std::endl;
	std::streampos uFileSize = file.tellg();	// return current character position(end of file in our case)

	char* pBuffer = nullptr;

	try
	{
		pBuffer = new char[(unsigned int)uFileSize];
	}
	catch (std::bad_alloc& e)
	{
		std::cout << e.what() << std::endl;
		return 0;
	}

	file.seekg(0, std::ios::beg);	// set pointer at the beginning
	file.read(pBuffer, uFileSize);
	file.close();
	std::cout << "DLL loaded into memory" << std::endl;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

	if (pDosHeader->e_magic != 0x5a4d)
	{
		std::cout << "Invalid file, exiting..." << std::endl;
		delete[] pBuffer;
		return 0;
	}

	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS(pBuffer + pDosHeader->e_lfanew);

	PIMAGE_OPTIONAL_HEADER pOptHeader = &pNTHeader->OptionalHeader;
	PIMAGE_FILE_HEADER pFileHeader = &pNTHeader->FileHeader;
	PIMAGE_SECTION_HEADER pSectHeader = IMAGE_FIRST_SECTION(pNTHeader);
	DWORD dwPID = GetProcPID(Settings["target"]);

	if (dwPID == -1)
	{
		std::cout << "Cannot find " << Settings["target"] << " , exiting..." << std::endl;
		delete[] pBuffer;
		return 0;
		
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		std::cout << "Cannot open specified process, exiting..." << std::endl;
		delete[] pBuffer;
		return 0;
	}
	std::cout << "Process opened" << std::endl;
	uint8_t* pAllocated = (uint8_t*)VirtualAllocEx(hProcess, NULL, pOptHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pAllocated)
	{
		std::cout << "Cannot allocate memory, exiting..." << std::endl;
		delete[] pBuffer;
		CloseHandle(hProcess);
		return 0;
	}
	std::cout << "Memory for sections allocated" << std::endl;
	for (uint32_t i = 0; i != pFileHeader->NumberOfSections; i++, pSectHeader++)
	{
		if (pSectHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProcess, (void*)(pAllocated + pSectHeader->VirtualAddress), pBuffer + pSectHeader->PointerToRawData, pSectHeader->SizeOfRawData, nullptr))
			{
				std::cout << "Cannot map section, exiting..." << std::endl;
				delete[] pBuffer;
				VirtualFreeEx(hProcess, pAllocated, 0, MEM_RELEASE);
				CloseHandle(hProcess);
				return 0;
			}
		}
	}
	std::cout << "Sections were mapped" << std::endl;
	LPVOID pShellcode = VirtualAllocEx(hProcess, NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		std::cout << "Cannot alloc memory, exiting..." << std::endl;
		delete[] pBuffer;
		VirtualFreeEx(hProcess, pAllocated, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 0;
	}
	std::cout << "Memory for shellcode allocated" << std::endl;
	Loader l;
	ZeroMemory(&l, sizeof(l));
	l.pGetProcAddress = GetProcAddress;
	l.pLoadLibrary = LoadLibrary;

	memcpy(pBuffer, &l, sizeof(l)); // rewrite 8 bytes
	WriteProcessMemory(hProcess, pAllocated, pBuffer, 0x1000, NULL);

	WriteProcessMemory(hProcess, pShellcode, &Shellcode, (DWORD)_size - (DWORD)Shellcode, NULL);

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pShellcode, pAllocated, NULL, NULL);

	if (hThread == INVALID_HANDLE_VALUE)
	{
		VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pAllocated, 0, MEM_RELEASE);
		delete[] pBuffer;
		CloseHandle(hProcess);
		std::cout << "Cannot create remote thread, exiting..." << std::endl;
		return 0;
	}
	std::cout << "Thread launched, waiting for response..." << std::endl;

	WaitForSingleObject(hThread, INFINITE);
	std::cout << "DLL injected succesfully" << std::endl;

	VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
	delete[] pBuffer;
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}