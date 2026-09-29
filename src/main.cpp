#include "pe/pe_image.hpp"
#include "x86/decoder.hpp"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

namespace {
constexpr std::uint32_t kImageScnMemExecute = 0x20000000u;
void disassemble_section(std::ostream& log, const pe::PEImage& image,
                         const pe::SectionHeader& section) {
    const std::uint64_t start = section.virtual_address;
    const std::uint64_t available = image.mapped_data.size();
    if (start >= available || section.size_of_raw_data == 0) {
        log << "\n[" << section.name << "] no file-backed bytes\n";
        return;
    }
    const std::uint64_t end = std::min<std::uint64_t>(available,
        start + std::min<std::uint64_t>(section.size_of_raw_data, available - start));
    std::vector<pe::Byte> code(image.mapped_data.begin() + static_cast<std::ptrdiff_t>(start),
                               image.mapped_data.begin() + static_cast<std::ptrdiff_t>(end));
    x86::Decoder decoder(code, static_cast<std::uint32_t>(image.image_base() + start));
    log << "\nDisassembly of section " << section.name << " (RVA 0x"
        << std::hex << std::uppercase << section.virtual_address << ", size 0x"
        << (end - start) << "):\n";
    std::size_t pos = 0;
    while (pos < code.size()) {
        auto ins = decoder.decode(pos);
        log << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
            << (image.image_base() + start + pos) << "  ";
        if (!ins.valid || ins.length == 0 || ins.length > code.size() - pos) {
            log << "<decode error>  db 0x" << std::setw(2)
                << static_cast<unsigned>(code[pos]) << '\n';
            ++pos;
            continue;
        }
        for (std::size_t j = 0; j < ins.length; ++j)
            log << std::setw(2) << static_cast<unsigned>(code[pos + j]) << ' ';
        for (std::size_t j = ins.length; j < 10; ++j) log << "   ";
        log << ' ' << ins.mnemonic;
        if (!ins.operands.empty()) log << ' ' << ins.operands;
        log << '\n';
        pos += ins.length;
    }
}
}

int main(int argc, char* argv[]) {
    const char* log_path = "disassembler.log";
    if (argc < 2) {
        std::cerr << "Usage: disassembler <pe_file> [log_file]\n";
        return 2;
    }
    if (argc >= 3) log_path = argv[2];
    std::ofstream log(log_path, std::ios::out | std::ios::trunc);
    if (!log) {
        std::cerr << "Cannot open log file: " << log_path << '\n';
        return 1;
    }
    try {
        auto image = pe::PEImage::load(argv[1]);
        log << "DISASSEMBLER v0.3.0\nPE32 x86 image\n"
            << "Image base: 0x" << std::hex << std::uppercase << image.image_base() << '\n'
            << "Entry point: 0x" << image.entry_point() << '\n'
            << "Image size: 0x" << image.optional.size_of_image << '\n'
            << "Sections: " << std::dec << image.sections.size() << '\n';
        bool found = false;
        for (const auto& section : image.sections) {
            log << "  " << section.name << " RVA=0x" << std::hex << section.virtual_address
                << " raw=0x" << section.pointer_to_raw_data
                << " raw-size=0x" << section.size_of_raw_data
                << " characteristics=0x" << section.characteristics << '\n';
            if ((section.characteristics & kImageScnMemExecute) != 0) {
                found = true;
                disassemble_section(log, image, section);
            }
        }
        if (!found) log << "\nNo executable sections found.\n";
    } catch (const std::exception& e) {
        log << "PE load error: " << e.what() << '\n';
        std::cerr << "PE load error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
