#include "hide_soinfo.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int find_linker64(uint64_t *base, char *path, size_t path_size) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "linker64") || strstr(line, ".so"))
            continue;
        if (!strstr(line, "r--p"))
            continue;

        uint64_t start;
        if (sscanf(line, "%lx-", &start) != 1)
            continue;

        char *slash = strrchr(line, '/');
        if (!slash || !strstr(slash, "linker64"))
            continue;

        char *path_start = strchr(line, '/');
        if (path_start) {
            char *nl = strchr(path_start, '\n');
            if (nl)
                *nl = 0;
            strncpy(path, path_start, path_size - 1);
            path[path_size - 1] = 0;
        }

        *base = start;
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

uint64_t compute_load_bias(uint64_t base) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;
    if (memcmp(ehdr->e_ident, "\x7f" "ELF", 4) != 0 || ehdr->e_ident[4] != 2)
        return base;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD)
            return base - phdr[i].p_vaddr;
    }
    return base;
}

int resolve_linker_syms(const char *path, uint64_t base, linker_syms_t *out) {
    memset(out, 0, sizeof(*out));
    uint64_t bias = compute_load_bias(base);

    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    if (memcmp(ehdr.e_ident, "\x7f" "ELF", 4) != 0) {
        fclose(f);
        return -1;
    }

    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) {
        fclose(f);
        return -1;
    }
    fseek(f, ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, f) != ehdr.e_shnum) {
        free(shdrs);
        fclose(f);
        return -1;
    }

    Elf64_Shdr *symtab_sh = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_sh = &shdrs[i];
            break;
        }
    }
    if (!symtab_sh) {
        free(shdrs);
        fclose(f);
        return -1;
    }

    Elf64_Shdr *strtab_sh = &shdrs[symtab_sh->sh_link];
    char *strtab = malloc(strtab_sh->sh_size);
    if (!strtab) {
        free(shdrs);
        fclose(f);
        return -1;
    }
    fseek(f, strtab_sh->sh_offset, SEEK_SET);
    fread(strtab, 1, strtab_sh->sh_size, f);

    int nsyms = symtab_sh->sh_size / sizeof(Elf64_Sym);
    Elf64_Sym *syms = malloc(symtab_sh->sh_size);
    if (!syms) {
        free(strtab);
        free(shdrs);
        fclose(f);
        return -1;
    }
    fseek(f, symtab_sh->sh_offset, SEEK_SET);
    fread(syms, sizeof(Elf64_Sym), nsyms, f);
    fclose(f);

    struct {
        const char *name;
        uint64_t *slot;
    } wanted[] = {
        { "__dl__Z15solist_get_headv", &out->solist_get_head },
        { "__dl__ZL6solist", &out->solist },
        { "__dl__ZL11solist_head", &out->solist_head },
        { "__dl__ZL11solist_tail", &out->solist_tail },
        { "__dl__Z17solist_add_soinfoP6soinfo", &out->solist_add_soinfo },
        { "__dl__Z20solist_remove_soinfoP6soinfo", &out->solist_remove_soinfo },
        { "__dl__Z23find_containing_libraryPKv", &out->find_containing_library },
        { "__dl__ZNK6soinfo12get_realpathEv", &out->soinfo_get_path },
        { "__dl__ZNK6soinfo7get_pathEv", &out->soinfo_get_path },
        { "__dl__r_debug", &out->r_debug },
        { "__dl__ZL12r_debug_tail", &out->r_debug_tail },
    };
    int nwanted = sizeof(wanted) / sizeof(wanted[0]);
    int matched = 0;

    for (int i = 0; i < nsyms; i++) {
        if (syms[i].st_name == 0 || syms[i].st_value == 0)
            continue;
        if (syms[i].st_name >= strtab_sh->sh_size)
            continue;
        const char *name = strtab + syms[i].st_name;
        for (int j = 0; j < nwanted; j++) {
            if (*(wanted[j].slot) != 0)
                continue;
            if (strcmp(name, wanted[j].name) == 0 ||
                (strncmp(name, wanted[j].name, strlen(wanted[j].name)) == 0 &&
                 name[strlen(wanted[j].name)] == '.')) {
                /* Android 16 内部符号带 .llvm.<id> 后缀。 */
                *(wanted[j].slot) = bias + syms[i].st_value;
                matched++;
                break;
            }
        }
    }

    free(syms);
    free(strtab);
    free(shdrs);
    g_hide_result.sym_matched = matched;
    return 0;
}

int derive_next_offset(uint64_t fn_addr) {
    uint32_t *insns = (uint32_t *)fn_addr;
    int page_reg = -1;
    int next_offset = -1;

    /* Android 16 空链表快路径在第一条 RET 结束；next 写在后续分支。 */
    for (int i = 0; i < 32; i++) {
        uint32_t insn = insns[i];
        if ((insn & 0x9F000000) == 0x90000000) {
            if (page_reg < 0)
                page_reg = insn & 0x1F;
            continue;
        }
        if ((insn & 0xFFC00000) == 0xF9000000) {
            int rt = insn & 0x1F;
            int rn = (insn >> 5) & 0x1F;
            if (rt == 0 && rn != page_reg) {
                int imm12 = (insn >> 10) & 0xFFF;
                next_offset = imm12 * 8;
            }
        }
    }
    return next_offset;
}

uint64_t derive_sonext_ptr(uint64_t fn_addr) {
    uint32_t *insns = (uint32_t *)fn_addr;
    int page_reg = -1;
    uint64_t page = 0;
    uint64_t sonext = 0;
    for (int i = 0; i < 16; i++) {
        uint32_t insn = insns[i];
        if ((insn & 0x9F000000) == 0x90000000) {
            int rd = insn & 0x1F;
            int immlo = (insn >> 29) & 0x3;
            int immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = ((int64_t)((immhi << 2) | immlo) << 43) >> 31;
            uint64_t pc = fn_addr + (uint64_t)i * 4;
            page = (pc & ~0xFFFULL) + (uint64_t)imm;
            page_reg = rd;
            continue;
        }
        if ((insn & 0xFFC00000) == 0xF9000000) {
            int rt = insn & 0x1F;
            int rn = (insn >> 5) & 0x1F;
            if (rt == 0 && rn == page_reg && page) {
                int imm12 = (insn >> 10) & 0xFFF;
                sonext = page + (uint64_t)imm12 * 8;
            }
        }
    }
    return sonext;
}

uint64_t map_start_containing(const void *addr) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[512];
    uint64_t needle = (uint64_t)addr;
    uint64_t found = 0;
    while (fgets(line, sizeof(line), f)) {
        uint64_t start = 0, end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2)
            continue;
        if (needle >= start && needle < end) {
            found = start;
            break;
        }
    }
    fclose(f);
    return found;
}
