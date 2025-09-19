#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mach-o/loader.h>
#include <sys/mman.h>

#include "arm64.h"
#include "macho.h"
#include "patchfinder.h"

struct section_64* pf_find_section(void* macho, const char* segname, const char* sectname) {
    struct segment_command_64* segment = macho_get_segment_by_segname(macho, segname);
    struct section_64* section = macho_get_section_by_sectname(macho, segment, sectname);
    if(segment == NULL) return NULL;
    if(section == NULL) return NULL;

    return section;
}

// objc string support?
uint64_t pf_find_string(void* macho, const char* segname, const char* sectname, const char* string) {
    struct section_64* section = pf_find_section(macho, segname, sectname);
    if (section == NULL) return 0;

    const uint8_t* sectionData = (const uint8_t*)macho + section->offset;
    for (size_t i = 0; i + strlen(string) + 1 <= section->size; i++) {
        printf("[DEBUG] Looking in %s,%s: offset=0x%x size=0x%llx addr=0x%llx\n", segname, sectname, section->offset, section->size, section->addr);
        if (memcmp(sectionData + i, string, strlen(string)) == 0) {
            return section->offset + i;
        }
    }
    return 0;
}

const char* pf_find_string_data(void* macho, const char* segname, const char* sectname, const char* string) {
    struct section_64* section = pf_find_section(macho, segname, sectname);
    if (section == NULL) return NULL;

    const char* sectionData = (const char*)macho + section->offset;
    for (size_t j = 0; j + strlen(string) + 1 <= section->size; j++) {
        if (memcmp(sectionData + j, string, strlen(string)) == 0) {
            const char* result = sectionData + j;
            return result;
        }
    }
    return NULL;
}

uint64_t pf_step64(void* macho, struct section_64* section, uint64_t start, uint32_t insn, uint32_t mask) {
    struct segment_command_64* segment = macho_get_segment_by_section_ptr(macho, section);
    if(segment == NULL) return -1;
    if(segment->initprot & VM_PROT_EXECUTE) {
        uint8_t* sectionData = (uint8_t*)macho + section->offset;
        for(uint64_t i = 0; i + 4 <= section->size; i += 4) {
            uint32_t word = *(uint32_t*)(sectionData + i);
            if((word & mask) == insn) {
                return section->addr + i;
            }
        }
    }
    return -1;
}

// TODO: add decoding logic for more insns
uint64_t pf_xref64(void* macho, struct section_64* section, uint64_t from) {
    struct segment_command_64* segment = macho_get_segment_by_section_ptr(macho, section);
    if(segment == NULL) return -1;
    if (segment->initprot & VM_PROT_EXECUTE) {
        uint8_t* sectionData = (uint8_t*)macho + section->offset;
        for (uint64_t i = 0; i + 8 <= section->size; i += 4) {
            uint32_t insn = *(uint32_t*)(sectionData + i);
            uint64_t va = section->addr + i;

            uint64_t adrp_target = arm64_decode_adrp_insn(insn, va);
            if (adrp_target != -1) {
                uint32_t next_insn = *(uint32_t*)(sectionData + i + 4);
                uint64_t add_target = arm64_decode_add_insn(next_insn, adrp_target);

                if (add_target == from) {
                    return va;
                }
            }

            uint64_t adr_target = arm64_decode_adr_insn(insn, va);
            if(adr_target != -1) {
                if(adr_target == from) {
                    return va;
                }
            }
        }
    }
    return -1;
}

