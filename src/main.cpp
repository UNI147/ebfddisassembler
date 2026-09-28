#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "DISASSEMBLER v0.1.0\n"
                  << "Usage: disassembler <pe_file>\n";
        return 0;
    }

    std::cout << "DISASSEMBLER v0.1.0\n";
    std::cout << "Input file: " << argv[1] << '\n';

    // TODO: Load PE image.
    // TODO: Initialize AddressMapper.
    // TODO: Disassemble entry point.

    return 0;
}