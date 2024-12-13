#ifndef MINIMAL_LOADER_H
#define MINIMAL_LOADER_H

#include <windows.h>
#include <stdio.h>

typedef struct {
    BOOL isValid;
    WORD machine;
    DWORD entryPoint;
    DWORD imageBase;
    DWORD sectionCount;
    DWORD characteristics;
} ExecutableInfo;

typedef struct _IMAGE_DESCRIPTOR {
    LPVOID pImageBase;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader;
} IMAGE_DESCRIPTOR, *PIMAGE_DESCRIPTOR;

void printLoaderBanner(void);
void printProgress(const char* stage, const char* detail);
ExecutableInfo parseExecutable(const char* filePath);
void displayExecutableInfo(const ExecutableInfo* info);

BOOL ProcessRelocations(PIMAGE_DESCRIPTOR image);
BOOL ProcessImports(PIMAGE_DESCRIPTOR image);
BOOL ProtectSections(PIMAGE_DESCRIPTOR image);
int ExecuteImage(PIMAGE_DESCRIPTOR image);
void CleanupImage(PIMAGE_DESCRIPTOR image);

LPVOID AllocateImageMemory(PIMAGE_NT_HEADERS ntHeaders, const char* filePath);

BOOL LoadSections(PIMAGE_DESCRIPTOR image, LPVOID fileBuffer);

BOOL ResolveImportFunction(HMODULE library, PIMAGE_THUNK_DATA thunk, 
                          PIMAGE_THUNK_DATA originalThunk, LPVOID imageBase);

BOOL SetupStackForExecution(PIMAGE_DESCRIPTOR image);
BOOL ValidateEntryPoint(PIMAGE_DESCRIPTOR image);

#endif // MINIMAL_LOADER_H