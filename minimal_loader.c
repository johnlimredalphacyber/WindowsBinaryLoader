#include "minimal_loader.h"

void printLoaderBanner(void) {
    printf("================================\n");
    printf("Windows Binary Loader v1.0\n");
    printf("================================\n\n");
}

void printProgress(const char* stage, const char* detail) {
    printf("[*] %-8s: %s\n", stage, detail);
    fflush(stdout);
}

PIMAGE_DOS_HEADER getDosHeader(LPVOID fileBase) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printProgress("ERROR", "Invalid DOS signature");
        return NULL;
    }
    printProgress("PARSE", "Valid DOS header found");
    return dosHeader;
}

PIMAGE_NT_HEADERS getNtHeaders(LPVOID fileBase, PIMAGE_DOS_HEADER dosHeader) {
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printProgress("ERROR", "Invalid NT signature");
        return NULL;
    }
    printProgress("PARSE", "Valid NT headers found");
    return ntHeaders;
}

ExecutableInfo parseExecutable(const char* filePath) {
    ExecutableInfo info = {0};
    char details[256];
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    LPVOID fileBase = NULL;
    PIMAGE_DESCRIPTOR imageDesc = NULL;
    
    printProgress("INIT", "Starting executable parsing process");
    
    // Open file
    hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printProgress("ERROR", "Failed to open executable file");
        return info;
    }
    printProgress("FILE", "Successfully opened executable file");

    // Create file mapping
    hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        printProgress("ERROR", "Failed to create file mapping");
        CloseHandle(hFile);
        return info;
    }
    printProgress("MAPPING", "Created file mapping object");

    // Map view of file
    fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) {
        printProgress("ERROR", "Failed to map view of file");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return info;
    }
    printProgress("MEMORY", "Mapped file into memory");

    // Parse DOS header
    PIMAGE_DOS_HEADER dosHeader = getDosHeader(fileBase);
    if (!dosHeader) {
        goto cleanup;
    }

    // Parse NT headers
    PIMAGE_NT_HEADERS ntHeaders = getNtHeaders(fileBase, dosHeader);
    if (!ntHeaders) {
        goto cleanup;
    }

    // After parsing NT headers and before filling in executable info
    LPVOID allocatedBase = AllocateImageMemory(ntHeaders, filePath);
    if (!allocatedBase) {
        printProgress("ERROR", "Memory allocation failed");
        goto cleanup;
    }

    // Create image descriptor
    imageDesc = (PIMAGE_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 
                                           HEAP_ZERO_MEMORY, 
                                           sizeof(IMAGE_DESCRIPTOR));
    if (!imageDesc) {
        printProgress("ERROR", "Failed to allocate image descriptor");
        goto cleanup;
    }

    // Initialize image descriptor
    imageDesc->pImageBase = allocatedBase;
    imageDesc->pDosHeader = dosHeader;
    imageDesc->pNtHeaders = ntHeaders;
    imageDesc->pFileHeader = &ntHeaders->FileHeader;
    imageDesc->pOptionalHeader = &ntHeaders->OptionalHeader;

    // Load sections
    if (!LoadSections(imageDesc, fileBase)) {
        printProgress("ERROR", "Failed to load sections");
        goto cleanup;
    }

    // Process relocations FIRST
    printProgress("RELOC", "Starting relocation processing");
    if (!ProcessRelocations(imageDesc)) {
        printProgress("ERROR", "Failed to process relocations");
        goto cleanup;
    }

    // THEN process imports
    printProgress("IMPORTS", "Starting import resolution");
    if (!ProcessImports(imageDesc)) {
        printProgress("ERROR", "Failed to process imports");
        goto cleanup;
    }

    // Set section protections
    printProgress("PROTECT", "Setting final section protections");
    if (!ProtectSections(imageDesc)) {
        printProgress("ERROR", "Failed to set section protections");
        goto cleanup;
    }

    // Setup for execution
    printProgress("EXEC", "Setting up for execution");
    if (!SetupStackForExecution(imageDesc)) {
        printProgress("ERROR", "Failed to setup execution stack");
        goto cleanup;
    }

    if (!ValidateEntryPoint(imageDesc)) {
        printProgress("ERROR", "Failed to validate entry point");
        goto cleanup;
    }

    // Execute the image
    int execResult = ExecuteImage(imageDesc);
    sprintf_s(details, sizeof(details), "Image execution completed with result: %d", execResult);
    printProgress("EXEC", details);

    // Fill in executable info
    info.isValid = TRUE;
    info.machine = ntHeaders->FileHeader.Machine;
    info.entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    info.imageBase = (DWORD)imageDesc->pImageBase;
    info.sectionCount = ntHeaders->FileHeader.NumberOfSections;
    info.characteristics = ntHeaders->FileHeader.Characteristics;
    
    printProgress("SUCCESS", "Parsed executable information successfully");

cleanup:
    if (fileBase) UnmapViewOfFile(fileBase);
    if (hMapping) CloseHandle(hMapping);
    if (hFile) CloseHandle(hFile);
    if (imageDesc) {
        CleanupImage(imageDesc);
    }
    return info;
}

void displayExecutableInfo(const ExecutableInfo* info) {
    if (!info->isValid) {
        printf("\nExecutable parsing failed!\n");
        return;
    }

    printf("\nExecutable Information:\n");
    printf("----------------------\n");
    printf("Machine Type: 0x%04X\n", info->machine);
    printf("Entry Point: 0x%08X\n", info->entryPoint);
    printf("Image Base: 0x%08X\n", info->imageBase);
    printf("Section Count: %d\n", info->sectionCount);
    printf("Characteristics: 0x%08X\n", info->characteristics);
}

BOOL ProcessRelocations(PIMAGE_DESCRIPTOR image) {
    char details[256];
    DWORD relocDirRVA;
    
    // Get relocation directory RVA
    relocDirRVA = image->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    
    if (relocDirRVA == 0) {
        printProgress("RELOC", "No relocation directory found in executable");
        return TRUE;
    }

    DWORD_PTR deltaImageBase = (DWORD_PTR)((LPBYTE)image->pImageBase - image->pOptionalHeader->ImageBase);
    sprintf_s(details, sizeof(details), "Base address delta: 0x%p", (void*)deltaImageBase);
    printProgress("RELOC", details);
    
    if (deltaImageBase == 0) {
        printProgress("RELOC", "No relocations needed - image loaded at preferred base");
        return TRUE;
    }

    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image->pImageBase + relocDirRVA);
    
    if (!relocation->VirtualAddress) {
        printProgress("RELOC", "No relocations present in executable");
        return TRUE;
    }

    DWORD totalRelocations = 0;
    DWORD blockCount = 0;

    printProgress("RELOC", "Starting relocation processing");

    while (relocation->VirtualAddress) {
        blockCount++;
        LPBYTE destinationAddress = (LPBYTE)image->pImageBase + relocation->VirtualAddress;
        DWORD numberOfEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        PWORD relocationData = (PWORD)((LPBYTE)relocation + sizeof(IMAGE_BASE_RELOCATION));

        sprintf_s(details, sizeof(details), 
                "Block %d: VA: 0x%08X, Entries: %d", 
                blockCount,
                relocation->VirtualAddress,
                numberOfEntries);
        printProgress("RELOC", details);

        DWORD typeCount[16] = {0};  // Track count of each relocation type

        for (DWORD i = 0; i < numberOfEntries; i++) {
            WORD offset = relocationData[i] & 0xFFF;
            WORD type = relocationData[i] >> 12;
            typeCount[type]++;

            switch (type) {
                case IMAGE_REL_BASED_HIGHLOW:
                    *(PDWORD)(destinationAddress + offset) += (DWORD)deltaImageBase;
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *(PULONGLONG)(destinationAddress + offset) += deltaImageBase;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    // Skip, used for alignment
                    break;
                default:
                    sprintf_s(details, sizeof(details), 
                            "Unsupported relocation type: %d", type);
                    printProgress("WARNING", details);
                    break;
            }
        }

        // Print statistics for this block
        if (typeCount[IMAGE_REL_BASED_HIGHLOW] > 0) {
            sprintf_s(details, sizeof(details), 
                    "  32-bit relocations: %d", typeCount[IMAGE_REL_BASED_HIGHLOW]);
            printProgress("RELOC", details);
        }
        if (typeCount[IMAGE_REL_BASED_DIR64] > 0) {
            sprintf_s(details, sizeof(details), 
                    "  64-bit relocations: %d", typeCount[IMAGE_REL_BASED_DIR64]);
            printProgress("RELOC", details);
        }
        if (typeCount[IMAGE_REL_BASED_ABSOLUTE] > 0) {
            sprintf_s(details, sizeof(details), 
                    "  Alignment entries: %d", typeCount[IMAGE_REL_BASED_ABSOLUTE]);
            printProgress("RELOC", details);
        }

        totalRelocations += numberOfEntries;
        relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
    }

    sprintf_s(details, sizeof(details), 
            "Completed %d relocations in %d blocks", totalRelocations, blockCount);
    printProgress("RELOC", details);

    return TRUE;
}

BOOL ProcessImports(PIMAGE_DESCRIPTOR image) {
    char details[256];
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    DWORD importDirRVA;
    
    // Get import directory RVA
    importDirRVA = image->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    if (importDirRVA == 0) {
        printProgress("IMPORTS", "No import directory found in executable");
        return TRUE;
    }

    // Calculate import descriptor location
    importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image->pImageBase + importDirRVA);
    
    sprintf_s(details, sizeof(details), "Import directory found at RVA: 0x%08X", importDirRVA);
    printProgress("IMPORTS", details);
    
    printProgress("IMPORTS", "Starting import resolution process");
    
    // Process each imported DLL
    for (; importDesc->Name != 0; importDesc++) {
        LPCSTR libraryName = (LPCSTR)((LPBYTE)image->pImageBase + importDesc->Name);
        sprintf_s(details, sizeof(details), "Loading library: %s", libraryName);
        printProgress("IMPORTS", details);
        
        HMODULE library = LoadLibraryA(libraryName);
        if (!library) {
            sprintf_s(details, sizeof(details), "Failed to load library: %s (Error: 0x%08X)", 
                     libraryName, GetLastError());
            printProgress("ERROR", details);
            return FALSE;
        }

        // Get the IAT (Import Address Table) and INT (Import Name Table)
        PIMAGE_THUNK_DATA thunkIAT = NULL;
        PIMAGE_THUNK_DATA thunkINT = NULL;
        
        // Get the INT (Import Name Table)
        if (importDesc->OriginalFirstThunk) {
            thunkINT = (PIMAGE_THUNK_DATA)((LPBYTE)image->pImageBase + 
                                         importDesc->OriginalFirstThunk);
        }
        
        // Get the IAT (Import Address Table)
        thunkIAT = (PIMAGE_THUNK_DATA)((LPBYTE)image->pImageBase + 
                                      importDesc->FirstThunk);
        
        // Use INT if available, otherwise use IAT
        PIMAGE_THUNK_DATA thunkRef = thunkINT ? thunkINT : thunkIAT;
        DWORD functionCount = 0;

        // Process all functions for this DLL
        for (; thunkRef->u1.AddressOfData != 0; thunkRef++, thunkIAT++) {
            FARPROC functionAddress = NULL;
            
            if (IMAGE_SNAP_BY_ORDINAL(thunkRef->u1.Ordinal)) {
                // Import by ordinal
                DWORD ordinal = IMAGE_ORDINAL(thunkRef->u1.Ordinal);
                sprintf_s(details, sizeof(details), "  Resolving function by ordinal: %d", ordinal);
                printProgress("IMPORTS", details);
                
                functionAddress = GetProcAddress(library, (LPCSTR)(ULONG_PTR)ordinal);
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(
                    (LPBYTE)image->pImageBase + thunkRef->u1.AddressOfData);
                
                sprintf_s(details, sizeof(details), "  Resolving function by name: %s", 
                         importByName->Name);
                printProgress("IMPORTS", details);
                
                functionAddress = GetProcAddress(library, (LPCSTR)importByName->Name);
            }

            if (!functionAddress) {
                sprintf_s(details, sizeof(details), "Failed to resolve function (Error: 0x%08X)", 
                         GetLastError());
                printProgress("ERROR", details);
                return FALSE;
            }

            thunkIAT->u1.Function = (ULONGLONG)functionAddress;
            sprintf_s(details, sizeof(details), "  Resolved to address: 0x%p", functionAddress);
            printProgress("IMPORTS", details);
            
            functionCount++;
        }

        sprintf_s(details, sizeof(details), "Successfully resolved %d functions from %s", 
                 functionCount, libraryName);
        printProgress("IMPORTS", details);
        printProgress("IMPORTS", "-------------------");
    }

    printProgress("IMPORTS", "All imports successfully resolved");
    return TRUE;
}

BOOL ProtectSections(PIMAGE_DESCRIPTOR image) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(image->pNtHeaders);

    for (WORD i = 0; i < image->pFileHeader->NumberOfSections; i++) {
        DWORD oldProtect;
        DWORD newProtect = PAGE_READONLY;

        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            newProtect = PAGE_EXECUTE;
        }
        if (section[i].Characteristics & IMAGE_SCN_MEM_READ) {
            newProtect = PAGE_READONLY;
        }
        if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_READWRITE;
        }
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            section[i].Characteristics & IMAGE_SCN_MEM_READ) {
            newProtect = PAGE_EXECUTE_READ;
        }
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            section[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_EXECUTE_READWRITE;
        }

        if (!VirtualProtect((LPBYTE)image->pImageBase + section[i].VirtualAddress,
            section[i].Misc.VirtualSize,
            newProtect,
            &oldProtect)) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL SetupStackForExecution(PIMAGE_DESCRIPTOR image) {
    char details[256];
    SIZE_T stackSize = 1024 * 1024;  // 1MB stack
    LPVOID stackBase;
    
    sprintf_s(details, sizeof(details), "Allocating stack space: %d bytes", stackSize);
    printProgress("EXEC", details);
    
    stackBase = VirtualAlloc(NULL, stackSize, 
                            MEM_RESERVE | MEM_COMMIT, 
                            PAGE_READWRITE);
    
    if (!stackBase) {
        sprintf_s(details, sizeof(details), 
                "Failed to allocate stack (Error: 0x%08X)", GetLastError());
        printProgress("ERROR", details);
        return FALSE;
    }
    
    sprintf_s(details, sizeof(details), "Stack allocated at: 0x%p", stackBase);
    printProgress("EXEC", details);
    
    return TRUE;
}

BOOL ValidateEntryPoint(PIMAGE_DESCRIPTOR image) {
    char details[256];
    LPVOID entryPoint = (LPVOID)((LPBYTE)image->pImageBase + 
                                image->pOptionalHeader->AddressOfEntryPoint);
    
    sprintf_s(details, sizeof(details), "Entry point found at: 0x%p", entryPoint);
    printProgress("EXEC", details);
    
    // Verify entry point is within executable memory
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(entryPoint, &mbi, sizeof(mbi))) {
        printProgress("ERROR", "Failed to query entry point memory region");
        return FALSE;
    }
    
    sprintf_s(details, sizeof(details), 
            "Entry point memory protection: 0x%08X", mbi.Protect);
    printProgress("EXEC", details);
    
    if (!(mbi.Protect & PAGE_EXECUTE_READ) && 
        !(mbi.Protect & PAGE_EXECUTE_READWRITE)) {
        printProgress("ERROR", "Entry point is not in executable memory");
        return FALSE;
    }
    
    return TRUE;
}

int ExecuteImage(PIMAGE_DESCRIPTOR image) {
    char details[256];
    printProgress("EXEC", "Preparing for execution");
    
    // Setup stack
    if (!SetupStackForExecution(image)) {
        printProgress("ERROR", "Failed to setup execution stack");
        return -1;
    }
    
    // Validate entry point
    if (!ValidateEntryPoint(image)) {
        printProgress("ERROR", "Entry point validation failed");
        return -1;
    }
    
    typedef int (WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
    DLLMAIN entryPoint = (DLLMAIN)((LPBYTE)image->pImageBase + 
                                  image->pOptionalHeader->AddressOfEntryPoint);
    
    sprintf_s(details, sizeof(details), 
            "Calling entry point at offset: 0x%08X", 
            image->pOptionalHeader->AddressOfEntryPoint);
    printProgress("EXEC", details);
    
    printProgress("EXEC", "Executing image...");
    int result = entryPoint((HINSTANCE)image->pImageBase, DLL_PROCESS_ATTACH, NULL);
    
    sprintf_s(details, sizeof(details), "Execution completed with result: %d", result);
    printProgress("EXEC", details);
    
    return result;
}

void CleanupImage(PIMAGE_DESCRIPTOR image) {
    if (image) {
        if (image->pImageBase) {
            VirtualFree(image->pImageBase, 0, MEM_RELEASE);
        }
        HeapFree(GetProcessHeap(), 0, image);
    }
}

LPVOID AllocateImageMemory(PIMAGE_NT_HEADERS ntHeaders, const char* filePath) {
    char details[256];
    LPVOID imageBase;
    
    // Print memory requirements
    sprintf_s(details, sizeof(details), "Required memory size: 0x%08X bytes", 
             ntHeaders->OptionalHeader.SizeOfImage);
    printProgress("MEMORY", details);
    
    sprintf_s(details, sizeof(details), "Preferred base address: 0x%08X", 
             ntHeaders->OptionalHeader.ImageBase);
    printProgress("MEMORY", details);
    
    // Attempt allocation at preferred base
    imageBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase,
                           ntHeaders->OptionalHeader.SizeOfImage,
                           MEM_RESERVE | MEM_COMMIT,
                           PAGE_READWRITE);
    
    if (imageBase) {
        sprintf_s(details, sizeof(details), "Successfully allocated at preferred base 0x%p", 
                 imageBase);
        printProgress("MEMORY", details);
    } else {
        // Try allocating at any available location
        printProgress("MEMORY", "Failed to allocate at preferred base, trying alternate location");
        imageBase = VirtualAlloc(NULL,
                               ntHeaders->OptionalHeader.SizeOfImage,
                               MEM_RESERVE | MEM_COMMIT,
                               PAGE_READWRITE);
        
        if (imageBase) {
            sprintf_s(details, sizeof(details), "Allocated at alternate location 0x%p", 
                     imageBase);
            printProgress("MEMORY", details);
        } else {
            printProgress("ERROR", "Failed to allocate memory for image");
        }
    }
    
    if (imageBase) {
        sprintf_s(details, sizeof(details), "Allocated %d sections with total size 0x%08X",
                 ntHeaders->FileHeader.NumberOfSections,
                 ntHeaders->OptionalHeader.SizeOfImage);
        printProgress("MEMORY", details);
    }
    
    return imageBase;
}

BOOL LoadSections(PIMAGE_DESCRIPTOR image, LPVOID fileBuffer) {
    char details[256];
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(image->pNtHeaders);
    
    sprintf_s(details, sizeof(details), "Loading %d sections", image->pFileHeader->NumberOfSections);
    printProgress("SECTIONS", details);

    // Copy headers
    memcpy(image->pImageBase, fileBuffer, image->pOptionalHeader->SizeOfHeaders);
    printProgress("SECTIONS", "Copied PE headers to image");

    // Copy each section
    for (WORD i = 0; i < image->pFileHeader->NumberOfSections; i++) {
        sprintf_s(details, sizeof(details), 
                "Section %d: %s", i + 1, (char*)section[i].Name);
        printProgress("SECTIONS", details);

        sprintf_s(details, sizeof(details), 
                "Virtual Address: 0x%08X, Size: 0x%08X", 
                section[i].VirtualAddress, 
                section[i].Misc.VirtualSize);
        printProgress("SECTIONS", details);

        if (section[i].SizeOfRawData > 0) {
            LPVOID destinationAddress = (LPBYTE)image->pImageBase + section[i].VirtualAddress;
            LPVOID sourceAddress = (LPBYTE)fileBuffer + section[i].PointerToRawData;
            
            memcpy(destinationAddress, sourceAddress, section[i].SizeOfRawData);
            
            sprintf_s(details, sizeof(details), 
                    "Copied 0x%08X bytes from file offset 0x%08X", 
                    section[i].SizeOfRawData, 
                    section[i].PointerToRawData);
            printProgress("SECTIONS", details);

            // Display section characteristics
            if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) 
                printProgress("SECTIONS", "  Attribute: Executable");
            if (section[i].Characteristics & IMAGE_SCN_MEM_READ) 
                printProgress("SECTIONS", "  Attribute: Readable");
            if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) 
                printProgress("SECTIONS", "  Attribute: Writable");
            if (section[i].Characteristics & IMAGE_SCN_CNT_CODE) 
                printProgress("SECTIONS", "  Content: Code");
            if (section[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) 
                printProgress("SECTIONS", "  Content: Initialized Data");
            if (section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) 
                printProgress("SECTIONS", "  Content: Uninitialized Data");
        } else {
            sprintf_s(details, sizeof(details), 
                    "Section contains no raw data (BSS or similar)");
            printProgress("SECTIONS", details);
        }
        printProgress("SECTIONS", "-------------------");
    }

    printProgress("SECTIONS", "All sections loaded successfully");
    return TRUE;
}