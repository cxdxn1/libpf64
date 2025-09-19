#ifndef patchfinder_h
#define patchfinder_h

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "macho.h"

struct section_64* pf_find_section(void* macho, const char* segname, const char* sectname);
uint64_t pf_find_section_addr(void* macho, const char* segname, const char* sectname);
uint64_t pf_find_string(void* macho, const char* segname, const char* sectname, const char* string);
const char* pf_find_string_data(void* macho, const char* segname, const char* sectname, const char* string);

uint64_t pf_step64(void* macho, struct section_64* section, uint64_t from, uint32_t what, uint32_t mask);
uint64_t pf_xref64(void* macho, struct section_64* section, uint64_t from);

#endif /* patchfinder_h */