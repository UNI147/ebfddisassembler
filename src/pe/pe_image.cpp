#include "pe_image.hpp"
#include <algorithm>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <iterator>
namespace pe {
namespace {
template<class T> T read_le(const std::vector<Byte>& b, Offset at) {
 if (at > b.size() || sizeof(T) > b.size()-static_cast<size_t>(at)) throw std::runtime_error("Truncated PE header");
 T v=0; for(size_t i=0;i<sizeof(T);++i) v |= static_cast<T>(b[static_cast<size_t>(at)+i]) << (8*i); return v;
}
void range(Offset at, Offset n, size_t size, const char* what) {
 if(at>size || n>size-at) throw std::runtime_error(std::string("Invalid PE range: ")+what);
}
}
PEImage PEImage::load(const std::string& path) {
 PEImage x; std::ifstream f(path,std::ios::binary); if(!f) throw std::runtime_error("Cannot open input file: "+path);
 x.file_data.assign(std::istreambuf_iterator<char>(f),{}); const auto& b=x.file_data;
 if(b.size()<64 || read_le<Word>(b,0)!=0x5a4d) throw std::runtime_error("Invalid DOS signature");
 x.dos.magic=read_le<Word>(b,0); x.dos.pe_offset=read_le<Dword>(b,0x3c);
 range(x.dos.pe_offset,24,b.size(),"PE/COFF headers");
 if(read_le<Dword>(b,x.dos.pe_offset)!=0x00004550) throw std::runtime_error("Invalid PE signature");
 Offset c=x.dos.pe_offset+4; x.coff={read_le<Word>(b,c),read_le<Word>(b,c+2),read_le<Dword>(b,c+4),read_le<Dword>(b,c+8),read_le<Dword>(b,c+12),read_le<Word>(b,c+16),read_le<Word>(b,c+18)};
 if(x.coff.machine!=0x14c) throw std::runtime_error("Only x86 PE32 (I386) is supported");
 Offset o=c+20; range(o,x.coff.size_of_optional_header,b.size(),"optional header");
 if(x.coff.size_of_optional_header<96 || read_le<Word>(b,o)!=0x10b) throw std::runtime_error("Only PE32 optional headers are supported");
 auto& h=x.optional; h.magic=read_le<Word>(b,o); h.major_linker_version=read_le<Byte>(b,o+2); h.minor_linker_version=read_le<Byte>(b,o+3);
 h.size_of_code=read_le<Dword>(b,o+4); h.size_of_initialized_data=read_le<Dword>(b,o+8); h.size_of_uninitialized_data=read_le<Dword>(b,o+12); h.address_of_entry_point=read_le<Dword>(b,o+16); h.base_of_code=read_le<Dword>(b,o+20); h.base_of_data=read_le<Dword>(b,o+24); h.image_base=read_le<Dword>(b,o+28); h.section_alignment=read_le<Dword>(b,o+32); h.file_alignment=read_le<Dword>(b,o+36);
 h.major_os_version=read_le<Word>(b,o+40); h.minor_os_version=read_le<Word>(b,o+42); h.major_image_version=read_le<Word>(b,o+44); h.minor_image_version=read_le<Word>(b,o+46); h.major_subsystem_version=read_le<Word>(b,o+48); h.minor_subsystem_version=read_le<Word>(b,o+50); h.win32_version_value=read_le<Dword>(b,o+52); h.size_of_image=read_le<Dword>(b,o+56); h.size_of_headers=read_le<Dword>(b,o+60); h.checksum=read_le<Dword>(b,o+64); h.subsystem=read_le<Word>(b,o+68); h.dll_characteristics=read_le<Word>(b,o+70); h.size_of_stack_reserve=read_le<Dword>(b,o+72); h.size_of_stack_commit=read_le<Dword>(b,o+76); h.size_of_heap_reserve=read_le<Dword>(b,o+80); h.size_of_heap_commit=read_le<Dword>(b,o+84); h.loader_flags=read_le<Dword>(b,o+88); h.number_of_rva_and_sizes=read_le<Dword>(b,o+92);
 if(!h.size_of_image || h.size_of_headers>b.size() || h.size_of_headers>h.size_of_image) throw std::runtime_error("Invalid image/header size");
 Offset dd=o+96; auto nd=std::min<Dword>(h.number_of_rva_and_sizes,static_cast<Dword>((x.coff.size_of_optional_header-96)/8));
 for(Dword i=0;i<nd;++i)x.directories.push_back({read_le<RVA>(b,dd+i*8),read_le<Dword>(b,dd+i*8+4)});
 Offset st=o+x.coff.size_of_optional_header; range(st,static_cast<Offset>(x.coff.number_of_sections)*40,b.size(),"section table");
 x.mapped_data.resize(h.size_of_image); std::copy_n(b.begin(),h.size_of_headers,x.mapped_data.begin());
 for(Word i=0;i<x.coff.number_of_sections;++i){Offset s=st+i*40; std::string name; for(int j=0;j<8&&b[s+j];++j)name.push_back(static_cast<char>(b[s+j])); SectionHeader sh{name,read_le<Dword>(b,s+8),read_le<RVA>(b,s+12),read_le<Dword>(b,s+16),read_le<Dword>(b,s+20),read_le<Dword>(b,s+36)};
  Offset extent=std::max(sh.virtual_size,sh.size_of_raw_data); range(sh.virtual_address,extent,h.size_of_image,"section virtual range"); range(sh.pointer_to_raw_data,sh.size_of_raw_data,b.size(),"section raw range"); if(sh.size_of_raw_data) std::copy_n(b.begin()+static_cast<size_t>(sh.pointer_to_raw_data),sh.size_of_raw_data,x.mapped_data.begin()+sh.virtual_address); x.sections.push_back(std::move(sh)); }
 return x;
}
std::optional<RVA> AddressMapper::va_to_rva(VA va) const { VA b=image_.image_base(); if(va<b||va-b>UINT32_MAX)return {}; auto r=static_cast<RVA>(va-b); if(r>=image_.optional.size_of_image)return {}; return r; }
std::optional<VA> AddressMapper::rva_to_va(RVA rva) const { if(rva>=image_.optional.size_of_image)return {}; return image_.image_base()+rva; }
std::optional<Offset> AddressMapper::rva_to_file_offset(RVA rva) const { if(rva<image_.optional.size_of_headers)return rva<image_.file_data.size()?std::optional<Offset>(rva):std::nullopt; for(auto&s:image_.sections)if(rva>=s.virtual_address){Offset d=static_cast<Offset>(rva)-s.virtual_address;if(d<s.size_of_raw_data){Offset p=s.pointer_to_raw_data+d;if(p<image_.file_data.size())return p;}}return {}; }
std::optional<RVA> AddressMapper::file_offset_to_rva(Offset p) const { if(p<image_.optional.size_of_headers)return p<=UINT32_MAX&&p<image_.file_data.size()?std::optional<RVA>(static_cast<RVA>(p)):std::nullopt;for(auto&s:image_.sections)if(p>=s.pointer_to_raw_data){Offset d=p-s.pointer_to_raw_data;if(d<s.size_of_raw_data&&static_cast<Offset>(s.virtual_address)+d<=UINT32_MAX)return static_cast<RVA>(s.virtual_address+d);}return {}; }
std::optional<Offset> AddressMapper::rva_to_image_offset(RVA rva) const { if(rva>=image_.mapped_data.size())return {}; return static_cast<Offset>(rva); }
}
