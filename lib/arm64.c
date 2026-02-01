#include <stdint.h>
#include <stdlib.h>
#include "arm64.h"

static inline int64_t arm64_sxt64(int64_t imm, uint8_t numBits) {
    imm = ((uint64_t)imm) << (64 - numBits);
    int64_t imm64 = imm >> (64 - numBits);
    return imm64;
}

// Note to self - you always right shift by the smallest bit index in the field you're trying to extract

uint64_t arm64_decode_bl_insn(uint32_t insn, uint64_t addr) {
    if((insn & 0xFC000000) != 0x94000000) return 0;
    uint32_t imm26 = insn & 0x03FFFFFF;
    int64_t offset = arm64_sxt64(imm26, 26) << 2;

    uint64_t target = addr + offset;
    return target;
}

uint64_t arm64_decode_add_insn(uint32_t insn, uint64_t addr) {
    if((insn & 0x7F000000) != 0x11000000) return 0;
    uint32_t imm12 = (insn >> 12) & 0xFFF;
    uint32_t shift = (insn >> 22) & 0x1;

    if(shift != 0) imm12 <<= 12;
    uint64_t target = addr + imm12;
    return target;
}

uint64_t arm64_decode_adr_insn(uint32_t insn, uint64_t addr) {
    if((insn & 0x9F000000) != 0x10000000) return 0;
    uint32_t immlo = (insn >> 29) & 0x3;
    uint32_t immhi = (insn >> 5) & 0x7FFFF;
    int64_t imm21 = arm64_sxt64((immhi << 2) | immlo, 21);

    uint64_t target = addr + imm21;
    return target;
}

uint64_t arm64_decode_adrp_insn(uint32_t insn, uint64_t addr) {
    if((insn & 0x9F000000) != 0x90000000) return 0;
    uint32_t immlo = (insn >> 29) & 0x3;
    uint32_t immhi = (insn >> 5) & 0x7FFFF;
    uint64_t offset = (uint64_t)(immhi << 2 | immlo) << 12;
    addr &=~ ADRP_PAGEMASK;
    int64_t imm21 = arm64_sxt64(offset, 33);

    uint64_t target = addr + imm21;
    return target;
}
