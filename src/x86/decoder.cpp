#include "x86/decoder.hpp"
#include <iomanip>
#include <array>
#include <sstream>
namespace x86 { namespace {
std::string hex(std::uint32_t n){std::ostringstream s;s<<"0x"<<std::uppercase<<std::hex<<n;return s.str();}
const char* regs32[]={"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
const char* regs16[]={"ax","cx","dx","bx","sp","bp","si","di"};
const char* regs8[]={"al","cl","dl","bl","ah","ch","dh","bh"};
}
Instruction Decoder::decode(std::size_t p) const {
 Instruction out; out.address=base_+static_cast<std::uint32_t>(p); if(p>=bytes_.size())return out;
 auto u=[&](std::size_t i)->std::uint8_t{return p+i<bytes_.size()?bytes_[p+i]:0;};
 std::size_t i=0; bool op16=false,addr16=false; const char* segment=nullptr; bool lock=false; const char* repeat=nullptr;
 while(i<15 && p+i<bytes_.size()){ auto b=u(i); if(b==0x66){op16=true;++i;} else if(b==0x67){addr16=true;++i;} else if(b==0xF0){lock=true;++i;} else if(b==0xF2){repeat="repne";++i;} else if(b==0xF3){repeat="rep";++i;} else if(b==0x2E){segment="cs";++i;} else if(b==0x36){segment="ss";++i;} else if(b==0x3E){segment="ds";++i;} else if(b==0x26){segment="es";++i;} else if(b==0x64){segment="fs";++i;} else if(b==0x65){segment="gs";++i;} else break; }
 if(i>=15||p+i>=bytes_.size())return out; auto op=u(i++); std::string m,a; unsigned width=op16?16:32;
 auto imm=[&](unsigned n){std::uint32_t v=0;for(unsigned k=0;k<n;k++)v|=std::uint32_t(u(i++))<<(8*k);return v;};
 auto modrm=[&](unsigned w)->std::pair<std::string,std::string>{auto x=u(i++);unsigned mod=x>>6,reg=(x>>3)&7,rm=x&7;std::string r= w==8?regs8[reg]:w==16?regs16[reg]:regs32[reg], q;
 if(mod==3)q=w==8?regs8[rm]:w==16?regs16[rm]:regs32[rm];else {std::ostringstream s;s<<"[";if(addr16){static const char* r16[]={"bx+si","bx+di","bp+si","bp+di","si","di","bp","bx"};if(mod==0&&rm==6)s<<hex(imm(2));else{s<<r16[rm];if(mod==1){auto d=(std::int8_t)u(i++);s<<(d<0?"-":"+")<<hex(d<0?-d:d);}else if(mod==2){auto d=(std::int16_t)imm(2);s<<(d<0?"-":"+")<<hex(d<0?-d:d);}}}else{if(rm==4){auto sib=u(i++);unsigned scale=1u<<(sib>>6),idx=(sib>>3)&7,bas=sib&7;if(idx!=4)s<<regs32[idx]<<"*"<<scale;if(mod==0&&bas==5){if(idx!=4)s<<"+";s<<hex(imm(4));}else{if(idx!=4)s<<"+";s<<regs32[bas];}}else if(mod==0&&rm==5)s<<hex(imm(4));else s<<regs32[rm];if(mod==1){auto d=(std::int8_t)u(i++);s<<(d<0?"-":"+")<<hex(d<0?-d:d);}else if(mod==2){auto d=(std::int32_t)imm(4);s<<(d<0?"-":"+")<<hex(d<0?-d:d);}}s<<"]";q=s.str();}return {r,q};};
 auto binary=[&](const char* name,unsigned w,bool reverse=false){auto [r,q]=modrm(w);m=name;a=reverse?r+", "+q:q+", "+r;};
 if(op==0x90)m="nop";else if(op>=0xA0&&op<=0xA3){unsigned w=(op==0xA0||op==0xA2)?8:width;auto address=imm(addr16?2:4);std::string mem="["+hex(address)+"]";std::string acc=w==8?"al":w==16?"ax":"eax";m="mov";a=(op==0xA0||op==0xA1)?acc+", "+mem:mem+", "+acc;}else if(op==0xC3)m="ret";else if(op==0xC2){m="ret";a=hex(imm(2));}
 else if(op==0xCC)m="int3";else if(op==0xCD){m="int";a=hex(imm(1));}
 else if(op==0x50||op==0x51||op==0x52||op==0x53||op==0x54||op==0x55||op==0x56||op==0x57){m="push";a=regs32[op-0x50];}
 else if(op>=0x58&&op<=0x5F){m="pop";a=regs32[op-0x58];}
 else if(op>=0xB8&&op<=0xBF){m="mov";a=std::string(op16?regs16[op-0xB8]:regs32[op-0xB8])+", "+hex(imm(op16?2:4));}
 else if(op==0x89)binary("mov",width);else if(op==0x8B)binary("mov",width,true);else if(op==0x88)binary("mov",8);else if(op==0x8A)binary("mov",8,true);
 else if(op==0x01)binary("add",width);else if(op==0x03)binary("add",width,true);else if(op==0x29)binary("sub",width);else if(op==0x2B)binary("sub",width,true);else if(op==0x31)binary("xor",width);else if(op==0x33)binary("xor",width,true);else if(op==0x39)binary("cmp",width);else if(op==0x3B)binary("cmp",width,true);else if(op==0x85)binary("test",width);
 else if(op==0xE8||op==0xE9||op==0xEB||(op>=0x70&&op<=0x7F)){int n=(op==0xEB||(op>=0x70&&op<=0x7F))?1:4;std::int32_t d=n==1?(std::int8_t)imm(1):(std::int32_t)imm(4);m=op==0xE8?"call":(op==0xE9||op==0xEB)?"jmp":std::string("j")+std::array<const char*,16>{"o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"}[op&15];a=hex(out.address+static_cast<std::uint32_t>(i)+d);}
 else if(op==0x68||op==0x6A){m="push";a=hex(imm(op==0x6A?1:op16?2:4));}
 else if(op==0xC7||op==0xC6){auto [r,q]=modrm(op==0xC6?8:width);m="mov";a=q+", "+hex(imm(op==0xC6?1:op16?2:4));}
 else if(op>=0x80&&op<=0x83){static const char* names[]={"add","or","adc","sbb","and","sub","xor","cmp"};unsigned w=(op==0x80||op==0x82)?8:width;auto x=u(i);unsigned g=(x>>3)&7;auto [r,q]=modrm(w);unsigned n=(op==0x80||op==0x82)?1:(op==0x81?(op16?2:4):1);std::uint32_t v=imm(n);if(op==0x83)v=static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int8_t>(v)));m=names[g];a=q+", "+hex(v);}
 else if(op>=0xC0&&op<=0xC1){static const char* names[]={"rol","ror","rcl","rcr","shl","shr","sal","sar"};unsigned w=op==0xC0?8:width;auto x=u(i);unsigned g=(x>>3)&7;auto [r,q]=modrm(w);m=names[g];a=q+", "+hex(imm(1));}
 else if(op==0xD0||op==0xD1||op==0xD2||op==0xD3){static const char* names[]={"rol","ror","rcl","rcr","shl","shr","sal","sar"};unsigned w=(op==0xD0||op==0xD2)?8:width;auto x=u(i);unsigned g=(x>>3)&7;auto [r,q]=modrm(w);m=names[g];a=q+", "+((op==0xD0||op==0xD1)?"1":"cl");}
 else if(op==0xFF){static const char* names[]={"inc","dec","call","callf","jmp","jmpf","push",""};auto x=u(i);unsigned g=(x>>3)&7;auto [r,q]=modrm(width);m=names[g];a=q;}
 else if(op==0xF6||op==0xF7){static const char* names[]={"test","","not","neg","mul","imul","div","idiv"};unsigned w=op==0xF6?8:width;auto x=u(i);unsigned g=(x>>3)&7;auto [r,q]=modrm(w);m=names[g];a=q;if(g==0)a+=", "+hex(imm(op==0xF6?1:op16?2:4));}
 else if(op==0x81||op==0x83){m="db";a=hex(op);}
 else if(op==0x0F){auto op2=u(i++);if(op2>=0x80&&op2<=0x8F){static const char* cc[]={"o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"};auto d=static_cast<std::int32_t>(imm(4));m=std::string("j")+cc[op2&15];a=hex(out.address+static_cast<std::uint32_t>(i)+d);}else if(op2==0xAF){auto [r,q]=modrm(width);m="imul";a=r+", "+q;}else if(op2==0xB6||op2==0xB7||op2==0xBE||op2==0xBF){auto [r,q]=modrm((op2==0xB6||op2==0xBE)?8:16);m=(op2==0xB6||op2==0xB7)?"movzx":"movsx";a=(op16?regs16:regs32)[0];a=(op16?regs16:regs32)[(u(i-1)>>3)&7]+std::string(", ")+q;}else {m="db";a=hex(0x0F);i--;}}
 else if(op==0xA8||op==0xA9){m="test";a=std::string(op==0xA8?"al":"eax")+", "+hex(imm(op==0xA8?1:op16?2:4));}
 else if(op==0xA4||op==0xA5||op==0xAA||op==0xAB||op==0xAC||op==0xAD){m=(op==0xA4||op==0xA5)?"movs":(op==0xAA||op==0xAB)?"stos":"lods";if(op&1)m+=op16?"w":"d";else m+="b";}
 else {m="db";a=hex(op);}
 if(i>bytes_.size()-p||i>15)return out; if(segment && a.find("[")!=std::string::npos){auto at=a.find("[");a.insert(at,std::string(segment)+":");} if(lock)m="lock "+m; if(repeat)m=std::string(repeat)+" "+m; out.length=static_cast<std::uint8_t>(i);out.mnemonic=m;out.operands=a;out.valid=true;return out;
}
}
