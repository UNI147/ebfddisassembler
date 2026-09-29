#include "x86/decoder.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

namespace x86 {

Decoder::Decoder(const std::vector<std::uint8_t>& bytes, std::uint32_t base)
    : bytes_(bytes), base_(base) {}

Instruction Decoder::decode(std::size_t offset) const {
    Instruction out{};
    out.address = base_ + static_cast<std::uint32_t>(offset);
    if (offset >= bytes_.size()) return out;

    // PE32 is decoded in legacy 32-bit mode. Zydis handles legacy prefixes,
    // opcode maps, ModR/M, SIB, displacement and immediate fields, including
    // x87, MMX, SSE and later extensions that are valid in this mode.
    ZydisDecoder decoder{};
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
            ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32))) {
        return out;
    }

    ZydisDecodedInstruction instruction{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    const auto remaining = bytes_.size() - offset;
    const auto available = std::min<std::size_t>(remaining,
        ZYDIS_MAX_INSTRUCTION_LENGTH);
    const auto* data = bytes_.data() + offset;

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, available,
            &instruction, operands.data()))) {
        // Keep the stream synchronized on invalid/truncated input. The caller
        // can emit this byte as data and continue at the next byte.
        out.length = 1;
        out.mnemonic = "db";
        constexpr char digits[] = "0123456789ABCDEF";
        const auto byte = data[0];
        out.operands = "0x";
        out.operands += digits[(byte >> 4) & 0x0F];
        out.operands += digits[byte & 0x0F];
        return out;
    }

    ZydisFormatter formatter{};
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter,
            ZYDIS_FORMATTER_STYLE_INTEL))) {
        return out;
    }

    std::array<char, 512> text{};
    if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter,
            &instruction, operands.data(), instruction.operand_count_visible,
            text.data(), text.size(), out.address, nullptr))) {
        return out;
    }

    out.length = instruction.length;
    out.valid = true;
    const std::string formatted(text.data());
    const auto separator = formatted.find_first_of(" \t");
    if (separator == std::string::npos) {
        out.mnemonic = formatted;
    } else {
        out.mnemonic = formatted.substr(0, separator);
        const auto first = formatted.find_first_not_of(" \t", separator);
        if (first != std::string::npos) out.operands = formatted.substr(first);
    }
    return out;
}

} // namespace x86
