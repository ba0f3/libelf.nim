type
  Elf64_Ehdr* = object
    e_ident*: array[0..15, cuchar]
    e_type*: cushort
    e_machine*: cushort
    e_version*: cuint
    e_entry*: culonglong
    e_phoff*: culonglong
    e_shoff*: culonglong
    e_flags*: cuint
    e_ehsize*: cushort
    e_phentsize*: cushort
    e_phnum*: cushort
    e_shenntsize*: cushort
    e_shnum*: cushort
    e_shstrndx*: cushort

  Elf64_Phdr* = object
    p_type*: cuint
    p_offset*: cuint
    p_vaddr*: culonglong
    p_paddr*: culonglong
    p_filesz*: culonglong
    p_memsz*: culonglong
    p_flags*: culonglong
    p_align*: culonglong

  Elf64_Shdr* = object
    sh_name*: cuint
    sh_type*: cuint
    sh_flags*: culonglong
    sh_addr*: culonglong
    sh_offset*: culonglong
    sh_size*: culonglong
    sh_link*: culonglong
    sh_info*: culonglong
    sh_addralign*: culonglong
    sh_entsize*: culonglong

  Elf64_Dyn_inner_union {.union.} = object
    d_val*: culonglong
    d_ptr*: culonglong

  Elf64_Dyn* = object
    d_tag*: clonglong
    d_un*: Elf64_Dyn_inner_union

  Elf64_Rel* = object
    r_offset*: culonglong
    r_info*: culonglong

  Elf64_Rela* = object
    r_offset*: culonglong
    r_info*: culonglong
    r_addend*: clonglong


  Elf64_Sym* = object
    st_name*: cuint
    st_info*: cuchar
    st_other*: cuchar
    st_shndx*: cushort
    st_value*: culonglong
    st_size*: culonglong
