#include <stdlib.h>
#include <mach-o/loader.h>
#include "file.h"

int file_open(const char* path, void** machoOut, size_t* sizeOut, struct mach_header_64** headerOut) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    void* buf = malloc(len);
    if (!buf) return -1;
    fread(buf, 1, len, fp);
    fclose(fp);

    *machoOut = buf;
    *sizeOut = len;
    *headerOut = (struct mach_header_64*)buf;
    return 0;
}

int file_write(const char* path, void* macho, size_t size) {
    FILE* fp = fopen(path, "wb");
    if(!fp) return -1;
    fwrite(macho, 1, size, fp);
    fflush(fp);
    fclose(fp);

    return 0;
}

int file_close(void* macho) {
    if(macho) free(macho);
    return 0;
}