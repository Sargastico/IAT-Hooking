// src: https://guidedhacking.com/threads/how-to-hook-import-address-table-iat-hooking.13555/

#include <stdio.h>
#include <windows.h>
#include <dbghlp.h>

// Macro to calculate addresses
#define PtrFromRva( base, rva ) ( ( ( PBYTE ) base ) + rva )

// Original function prototype (Sleep - kernel32.dll )
typedef void* (WINAPI *TrueSleep)(DWORD);
TrueSleep fnSleep;

// Hooked function prototype (same calling convention of the original)
void WINAPI MySleep(DWORD dwMiliseconds) {
    return;
}

BOOL HookIAT(const char *szModuleName, const char *szFuncName, PVOID pNewFunc, PVOID *pOldFunc) {

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL); // Null arguments gets .exe module base address
    PIMAGE_NT_HEADERS pNtHeader  = (PIMAGE_NT_HEADERS)PtrFromRva(pDosHeader, pDosHeader->e_lfanew); // Offset to PE file header: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
    /* MS-DOS STUB HEADER: https://wiki.osdev.org/PE#DOS_Stub, https://blog.kowalczyk.info/articles/pefileformat.html

        typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
            USHORT e_magic;         // Magic number
            USHORT e_cblp;          // Bytes on last page of file
            USHORT e_cp;            // Pages in file
            USHORT e_crlc;          // Relocations
            USHORT e_cparhdr;       // Size of header in paragraphs
            USHORT e_minalloc;      // Minimum extra paragraphs needed
            USHORT e_maxalloc;      // Maximum extra paragraphs needed
            USHORT e_ss;            // Initial (relative) SS value
            USHORT e_sp;            // Initial SP value
            USHORT e_csum;          // Checksum
            USHORT e_ip;            // Initial IP value
            USHORT e_cs;            // Initial (relative) CS value
            USHORT e_lfarlc;        // File address of relocation table
            USHORT e_ovno;          // Overlay number
            USHORT e_res[4];        // Reserved words
            USHORT e_oemid;         // OEM identifier (for e_oeminfo)
            USHORT e_oeminfo;       // OEM information; e_oemid specific
            USHORT e_res2[10];      // Reserved words
            LONG   e_lfanew;    <===== 4-byte offset into the file where the PE file header is located (necessary to locate the PE header)
        } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER; 
        */

    // Make sure we have valid data
    if(pNtHeader->Signature != IMAGE_NT_SIGNATURE) { // "IMAGE_NT_SIGNATURE" = A 4-byte signature identifying the file as a PE image. The bytes are "PE\0\0".
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)PtrFromRva(pDosHeader, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    /* Get Pointer to IDT (Import Directory Table) - IDT is an array of structs of type IMAGE_IMPORT_DESCRIPTOR: http://pinvoke.net/default.aspx/Structures/IMAGE_IMPORT_DESCRIPTOR.html

        Path to IDT Pointer:
        > OptionalHeader (https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32) 
        > DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] (https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)
        > VirtualAddress (https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory)

    */

    // Iterate over the IDT (array of structs of type IMAGE_IMPORT_DESCRIPTOR) to fetch modules
    for(UINT uIndex = 0; pImportDescriptor[uIndex].Characteristics !=0; uIndex++){

        // Gets modules (.dll) names
        char *szDllName = (char*)PtrFromRva(pDosHeader, pImportDescriptor[uIndex].Name);
        printf("[%s]\n", szDllName);


        if (!pImportDescriptor[uIndex].FirstThunk || !pImportDescriptor[uIndex].OriginalFirstThunk) {
            return FALSE;
        }

        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)PtrFromRva(pDosHeader, pImportDescriptor[uIndex].FirstThunk); // IAT Address
        PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)PtrFromRva(pDosHeader, pImportDescriptor[uIndex].OriginalFirstThunk); // ILT Address : https://doxygen.reactos.org/d2/da5/struct__IMAGE__THUNK__DATA32.html
        /*
         Import Lookup Table (ILT): 32-bits 
            > MSB "1" defines that the functuon will be imported as an ordinal 
            > MSB "0" defines that the functuon will be imported by name.
            > last 31 bits defines the address of the struct with the name of the function
        */

        // Process/Enumerate imported functions from modules.
        for (; pOrigThunk->u1.Function != NULL; pOrigThunk++, pThunk++){

            // Can't process ordinal imports just the named ones
            if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                continue;
            }

            // Gets imported function name
            PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME) PtrFromRva(pDosHeader, pOrigThunk->u1.AddressOfData);
            printf("\t%s\n", (char*)import->Name);

            // Compare if it's the function we are searching for
            if (_strcmpi(szFuncName, (char*)import->Name) != 0) {
                    continue;
            }

            DWORD dwJunk = 0; // Junk variable to store the temporary memory protection option ("VirtualProtect" requires it)
            MEMORY_BASIC_INFORMATION mbi; // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information

            // Make the memory section of IAT (pThunk) writable.
            VirtualQuery(pThunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION)); // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery
            if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect)){ //https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
                return FALSE;
            }

            // Save the old pointer
            *pOldFunc = (PVOID*)(DWORD_PTR)pThunk->u1.Function;

// Write the new pointer to the IAT based on CPU type
#ifdef _WIN64

            pThunk->u1.Function = (ULONGLONG)(DWORD_PTR)pNewFunc;

#else

            pThunk->u1.Function = (DWORD)(DWORD_PTR)pNewFunc;

#endif

            // Restore the IAT memory protection (not writable)
            if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwJunk)){
                return TRUE;
            }
        }
    }
    return FALSE;
}

// IAT Hook Kernel32!Sleep


// Updated MySleep function
void WINAPI MySleep(DWORD dwMiliseconds) {
    printf("\n[?] Hooked Sleep Function Called!\n");
    printf("Sleeping for: %ld\n", dwMiliseconds);
 
    // Call original function
    fnSleep(dwMiliseconds);
}
 
int main()
{
    PVOID pOldProc;
 
    if (!HookIAT("kernel32.dll", "Sleep", (PVOID)MySleep, &pOldProc)) {
        printf("[-] Hooking failed error (%ld)\n", GetLastError());
    }
    else {
        printf("[?] Old Address: 0x%p\n[+] New Address: 0x%p\n", pOldProc, MySleep);
                // Pointer to original function
        fnSleep = (TrueSleep)pOldProc;
        Sleep(10000);
    }
    return 0;
}


