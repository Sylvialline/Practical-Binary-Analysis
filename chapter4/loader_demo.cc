/* Demonstrate the binary loader from ../inc/loader.cc */

#include <stdio.h>
#include <stdint.h>
#include <string>

#include "../inc/loader.h"

int
main(int argc, char *argv[])
{
  size_t i;
  Binary bin;
  Section *sec;
  Symbol *sym;
  std::string fname;

  if(argc < 2) {
    printf("Usage: %s <binary> <section-name>...\n", argv[0]);
    return 1;
  }

  fname.assign(argv[1]);
  if(load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
    return 1;
  }

  printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n", 
         bin.filename.c_str(), 
         bin.type_str.c_str(), bin.arch_str.c_str(), 
         bin.bits, bin.entry);

  for(i = 0; i < bin.sections.size(); i++) {
    sec = &bin.sections[i];
    printf("  0x%016jx %-8ju %-20s %s\n", 
           sec->vma, sec->size, sec->name.c_str(), 
           sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
  }

  if(bin.symbols.size() > 0) {
    printf("scanned symbol tables\n");
    for(i = 0; i < bin.symbols.size(); i++) {
      sym = &bin.symbols[i];
      printf("  %-40s 0x%016jx %s\n", 
             sym->name.c_str(), sym->addr, 
             (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "OBJECT");
    }
  }

  if(argc >= 3) {
    const char *name, *type;
    for(i = 0; 2 + i < argc; i++) {
      name = argv[2 + i];
      printf("Section %s:\n", name);
      std::string sname(name);
      if(sname == ".shstrtab" || sname == ".symtab" || sname == ".strtab"){
        // bfd cannot read section `.shstrtab`, `.symtab` and `.strtab` directly even if they exsit.
        printf("  loader_demo cannot read section %s directly even if it exsits.\n", name);
        if(sname == ".shstrtab") printf("  You already have these section names.\n");
        else printf("  Go for 'scanned symbol tables'.\n");
        continue;
      }

      bool ok = false;
      for(auto &section: bin.sections) {
        if(section.name == sname) {
          ok = true;
          switch(section.type) {
          case Section::SectionType::SEC_TYPE_CODE:
            type = "CODE"; break;
          case Section::SectionType::SEC_TYPE_DATA:
            type = "DATA"; break;
          default:
            type = "NONE";
          }
          printf("  name: %s\n", name);
          printf("  type: %s\n", type);
          printf("  vma: %016jx\n", section.vma);
          printf("  size: %ju bytes\n", section.size);
          printf("  contents:");
          for(uint64_t off=0; off < section.size; off += 0x10) {
            printf("\n    0x%08jx:", off);
            for(int x = 0, y = 0; x < 4; x++){
              printf(" ");
              for(; y < (x+1) * 4; y++){
                if(off + y >= section.size) break;
                printf("%02x", section.bytes[off + y]);
              }
              if(off + y >= section.size) break;
            }
          }
          printf("\n");
          break;
        }
      }
      if(ok == false) {

        printf("  No such section!\n");
      }
      printf("\n");
    }
  }

  unload_binary(&bin);

  return 0;
}

