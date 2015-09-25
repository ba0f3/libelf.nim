type
  Elf32_Ehdr* = object
    e_ident*: array[0..15, cuchar]
    e_type*: cushort
    e_machine*: cushort
    e_version*: cuint
    e_entry*: cuint
    e_phoff*: cuint
    e_shoff*: cuint
    e_flags*: cuint
    e_ehsize*: cushort
    e_phentsize*: cushort
    e_phnum*: cushort
    e_shentsize*: cushort
    e_shnum*: cushort
    e_shstrndx*: cushort

  Elf32_Phdr* = object
    p_type*: cuint
    p_offset*: cuint
    p_vaddr*: cuint
    p_paddr*: cuint
    p_filesz*: cuint
    p_memsz*: cuint
    p_flags*: cuint
    p_align*: cuint

  Elf32_Shdr* = object
    sh_name*: cuint
    sh_type*: cuint
    sh_flags*: cuint
    sh_addr*: cuint
    sh_offset*: cuint
    sh_size*: cuint
    sh_link*: cuint
    sh_info*: cuint
    sh_addralign*: cuint
    sh_entsize*: cuint


  Elf32_Dyn_inner_union {.union.} = object
    d_val*: cint
    d_ptr*: cuint

  Elf32_Dyn* = object
    d_tag*: cint
    d_un*: Elf32_Dyn_inner_union

  Elf32_Rel* = object
    r_offset*: cuint
    r_info*: cuint

  Elf32_Rela* = object
    r_offset*: cuint
    r_info*: cuint
    r_addend*: cint


  Elf32_Sym* = object
    st_name*: cuint
    st_value*: cuint
    st_size*: cuint
    st_info*: cuchar
    st_other*: cuchar
    st_shndx*: cushort
