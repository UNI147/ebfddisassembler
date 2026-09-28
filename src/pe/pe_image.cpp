#pragma once

#include <optional>

#include "pe_image.hpp"

#include <limits>

namespace pe {

std::optional<RVA>
AddressMapper::va_to_rva(VA va) const {
    const VA base = image_.optional.image_base;

    if (va < base)
        return std::nullopt;

    const VA rva = va - base;

    if (rva > std::numeric_limits<RVA>::max())
        return std::nullopt;

    return static_cast<RVA>(rva);
}

std::optional<VA>
AddressMapper::rva_to_va(RVA rva) const {
    const VA base = image_.optional.image_base;

    if (rva > std::numeric_limits<VA>::max() - base)
        return std::nullopt;

    return base + rva;
}

std::optional<Offset>
AddressMapper::rva_to_file_offset(RVA rva) const {
    // Заголовки PE
    if (rva < image_.optional.size_of_headers) {
        if (rva >= image_.file_data.size())
            return std::nullopt;

        return static_cast<Offset>(rva);
    }

    // Секции
    for (const auto& section : image_.sections) {
        if (rva < section.virtual_address)
            continue;

        const RVA delta = rva - section.virtual_address;

        // В файле присутствуют только сырые данные секции.
        if (delta >= section.size_of_raw_data)
            continue;

        const Offset offset =
            static_cast<Offset>(section.pointer_to_raw_data) + delta;

        if (offset >= image_.file_data.size())
            return std::nullopt;

        return offset;
    }

    return std::nullopt;
}

std::optional<RVA>
AddressMapper::file_offset_to_rva(Offset offset) const {
    // Заголовки PE
    if (offset < image_.optional.size_of_headers) {
        if (offset >= image_.file_data.size())
            return std::nullopt;

        if (offset > std::numeric_limits<RVA>::max())
            return std::nullopt;

        return static_cast<RVA>(offset);
    }

    // Сырые данные секций
    for (const auto& section : image_.sections) {
        const Offset raw_start = section.pointer_to_raw_data;
        const Offset raw_size = section.size_of_raw_data;

        if (offset < raw_start)
            continue;

        const Offset delta = offset - raw_start;

        if (delta >= raw_size)
            continue;

        const uint64_t rva =
            static_cast<uint64_t>(section.virtual_address) + delta;

        if (rva > std::numeric_limits<RVA>::max())
            return std::nullopt;

        return static_cast<RVA>(rva);
    }

    return std::nullopt;
}

} // namespace pe