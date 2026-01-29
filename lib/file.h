#ifndef file_h
#define file_h

#include <stdio.h>

int file_open(const char* path, void** machoOut, size_t* sizeOut, struct mach_header_64** headerOut);
int file_write(const char* path, void* macho, size_t size);
int file_close(void* macho);

#endif /* file_h */