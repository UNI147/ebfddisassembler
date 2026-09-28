#include "pe/pe_image.hpp"
#include "x86/decoder.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
    const char* log_path = "disassembler.log";
    std::ofstream log(log_path, std::ios::out | std::ios::trunc);
    if (!log) {
        std::cerr << "Cannot open log file: " << log_path << '\n';
        return 1;
    }
    if (argc < 2) {
        log << "DISASSEMBLER v0.1.0\nUsage: disassembler <pe_file>\n";
        return 0;
    }
    try {
        auto image = pe::PEImage::load(argv[1]);
        pe::AddressMapper map(image);
        log << "DISASSEMBLER v0.1.0\nPE32 x86 loaded\n"
            << "Image base: 0x" << std::hex << std::uppercase << image.image_base() << '\n'
            << "Entry point: 0x" << image.entry_point() << '\n'
            << "Image size: 0x" << image.optional.size_of_image << '\n'
            << "Sections: " << std::dec << image.sections.size() << '\n';
        for (const auto& section : image.sections) {
            log << "  " << section.name << " RVA=0x" << std::hex << section.virtual_address
                << " VA=0x" << *map.rva_to_va(section.virtual_address)
                << " raw=0x" << section.pointer_to_raw_data
                << " size=0x" << section.size_of_raw_data << '\n';
        }
        if (auto off = map.rva_to_file_offset(image.optional.address_of_entry_point)) {
            log << "Entry file offset: 0x" << *off
                << "\n\nDisassembly (entry point, up to 200 instructions):\n";
            std::vector<pe::Byte> code(image.mapped_data.begin() + image.optional.address_of_entry_point,
                                       image.mapped_data.end());
            x86::Decoder decoder(code, static_cast<std::uint32_t>(image.entry_point()));
            std::size_t pos = 0;
            for (unsigned n = 0; n < 200 && pos < code.size(); ++n) {
                auto ins = decoder.decode(pos);
                if (!ins.valid || !ins.length) {
                    log << std::hex << ins.address << ": <decode error>\n";
                    break;
                }
                log << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << ins.address << "  ";
                for (std::size_t j = 0; j < ins.length; ++j)
                    log << std::setw(2) << unsigned(code[pos + j]) << ' ';
                for (std::size_t j = ins.length; j < 8; ++j) log << "   ";
                log << ' ' << ins.mnemonic << ' ' << ins.operands << '\n';
                pos += ins.length;
            }
        } else {
            log << "Entry point has no file-backed byte\n";
        }
    } catch (const std::exception& e) {
        log << "PE load error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
