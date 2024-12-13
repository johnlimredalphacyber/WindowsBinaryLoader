#include "minimal_loader.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path_to_executable>\n", argv[0]);
        return 1;
    }

    printLoaderBanner();
    ExecutableInfo info = parseExecutable(argv[1]);
    displayExecutableInfo(&info);

    return 0;
}