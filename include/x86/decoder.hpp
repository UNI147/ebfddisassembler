#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace x86 {
struct Instruction { std::uint32_t address{}; std::uint8_t length{}; std::string mnemonic; std::string operands; bool valid{}; };
class Decoder {
public:
 explicit Decoder(const std::vector<std::uint8_t>& bytes, std::uint32_t base=0): bytes_(bytes), base_(base) {}
 Instruction decode(std::size_t offset) const;
private:
 const std::vector<std::uint8_t>& bytes_; std::uint32_t base_;
};
}
