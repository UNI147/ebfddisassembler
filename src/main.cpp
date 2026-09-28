#include "pe/pe_image.hpp"
#include <iomanip>
#include <iostream>
int main(int argc,char* argv[]) {
 if(argc<2){std::cout<<"DISASSEMBLER v0.1.0\nUsage: disassembler <pe_file>\n";return 0;}
 try { auto image=pe::PEImage::load(argv[1]); pe::AddressMapper map(image);
  std::cout<<"DISASSEMBLER v0.1.0\nPE32 x86 loaded\nImage base: 0x"<<std::hex<<std::uppercase<<image.image_base()<<"\nEntry point: 0x"<<image.entry_point()<<"\nImage size: 0x"<<image.optional.size_of_image<<"\nSections: "<<std::dec<<image.sections.size()<<"\n";
  for(const auto&s:image.sections)std::cout<<"  "<<s.name<<" RVA=0x"<<std::hex<<s.virtual_address<<" VA=0x"<<*map.rva_to_va(s.virtual_address)<<" raw=0x"<<s.pointer_to_raw_data<<" size=0x"<<s.size_of_raw_data<<"\n";
  if(auto off=map.rva_to_file_offset(image.optional.address_of_entry_point))std::cout<<"Entry file offset: 0x"<<*off<<"\n";else std::cout<<"Entry point has no file-backed byte\n";
 }catch(const std::exception&e){std::cerr<<"PE load error: "<<e.what()<<'\n';return 1;} return 0;
}
