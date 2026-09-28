#pragma once

#include <cstdint>
#include <string>

namespace pe {

using Byte   = std::uint8_t;
using Word   = std::uint16_t;
using Dword  = std::uint32_t;
using Qword  = std::uint64_t;
using Offset = std::uint64_t;
using VA     = std::uint64_t;
using RVA    = std::uint32_t;

struct DosHeader {
    Word magic;
    Dword pe_offset;
};

struct CoffHeader {
    Word machine;
    Word number_of_sections;
    Dword time_date_stamp;
    Dword pointer_to_symbol_table;
    Dword number_of_symbols;
    Word size_of_optional_header;
    Word characteristics;
};

struct OptionalHeader32 {
    Word magic;
    Byte major_linker_version;
    Byte minor_linker_version;
    Dword size_of_code;
    Dword size_of_initialized_data;
    Dword size_of_uninitialized_data;
    Dword address_of_entry_point;
    Dword base_of_code;
    Dword base_of_data;
    Dword image_base;
    Dword section_alignment;
    Dword file_alignment;
    Word major_os_version;
    Word minor_os_version;
    Word major_image_version;
    Word minor_image_version;
    Word major_subsystem_version;
    Word minor_subsystem_version;
    Dword win32_version_value;
    Dword size_of_image;
    Dword size_of_headers;
    Dword checksum;
    Word subsystem;
    Word dll_characteristics;
    Dword size_of_stack_reserve;
    Dword size_of_stack_commit;
    Dword size_of_heap_reserve;
    Dword size_of_heap_commit;
    Dword loader_flags;
    Dword number_of_rva_and_sizes;
};

struct DataDirectory {
    RVA virtual_address;
    Dword size;
};

struct SectionHeader {
    std::string name;
    Dword virtual_size;
    RVA virtual_address;
    Dword size_of_raw_data;
    Offset pointer_to_raw_data;
    Dword characteristics;
};

} // namespace pe