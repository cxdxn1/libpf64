#ifndef arm64_h 
#define arm64_h

#include <stdint.h>

#define ADRP_PAGESIZE 0x4000
#define ADRP_PAGEMASK  (ADRP_PAGESIZE - 1) // 0x3FFF if page size is 0x4000

uint64_t arm64_decode_add_insn(uint32_t insn, uint64_t addr);
uint64_t arm64_decode_adr_insn(uint32_t insn, uint64_t addr);
uint64_t arm64_decode_adrp_insn(uint32_t insn, uint64_t addr);

#endif /* arm64_h */