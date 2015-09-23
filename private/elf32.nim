type
  Elf32_Ehdr* = object
    e_ident*: array[0..15, cuchar]
    e_type*: uint16
    e_machine*: uint16
    e_version*: uint32
    e_entry*: uint32
    e_phoff*: uint32
    e_shoff*: uint32
    e_flags*: uint32
    e_ehsize*: uint16
    e_phentsize*: uint16
    e_phnum*: uint16
    e_shenntsize*: uint16
    e_shnum*: uint16
    e_shstrndx*: uint16

  Elf32_Phdr* = object
    p_type*: uint32
    p_offset*: uint32
    p_vaddr*: uint32
    p_paddr*: uint32
    p_filesz*: uint32
    p_memsz*: uint32
    p_flags*: uint32
    p_align*: uint32

  Elf32_Shdr* = object
    sh_name*: uint32
    sh_type*: uint32
    sh_flags*: uint32
    sh_addr*: uint32
    sh_offset*: uint32
    sh_size*: uint32
    sh_link*: uint32
    sh_info*: uint32
    sh_addralign*: uint32
    sh_entsize*: uint32


  Elf32_Dyn_inner_union {.union.} = object
    d_val*: int32
    d_ptr*: uint32

  Elf32_Dyn* = object
    d_tag*: int32
    d_un*: Elf32_Dyn_inner_union

  Elf32_Rel* = object
    r_offset: uint32
    r_info*: uint32

  Elf32_Rela* = object
    r_offset*: uint32
    r_info*: uint32
    r_addend*: int32


  Elf32_Sym* = object
    st_name*: uint32
    st_value*: uint32
    st_size*: uint32
    st_info*: cuchar
    st_other*: cuchar
    st_shndx*: uint16
