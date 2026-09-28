#pragma once
#include "pe_types.hpp"
#include <optional>
#include <string>
#include <vector>
namespace pe {
struct PEImage {
    std::vector<Byte> file_data;
    std::vector<Byte> mapped_data;
    DosHeader dos{}; CoffHeader coff{}; OptionalHeader32 optional{};
    std::vector<DataDirectory> directories;
    std::vector<SectionHeader> sections;
    [[nodiscard]] VA image_base() const noexcept { return optional.image_base; }
    [[nodiscard]] VA entry_point() const noexcept { return VA{optional.image_base}+optional.address_of_entry_point; }
    static PEImage load(const std::string& path);
};
class AddressMapper {
public:
 explicit AddressMapper(const PEImage& image): image_(image) {}
 std::optional<RVA> va_to_rva(VA va) const;
 std::optional<VA> rva_to_va(RVA rva) const;
 std::optional<Offset> rva_to_file_offset(RVA rva) const;
 std::optional<RVA> file_offset_to_rva(Offset offset) const;
 std::optional<Offset> rva_to_image_offset(RVA rva) const;
private: const PEImage& image_;
};
}
