type
  Elf64_Ehdr* = object
    e_ident*: array[0..15, cuchar]
    e_type*: uint16
    e_machine*: uint16
    e_version*: uint32
    e_entry*: uint64
    e_phoff*: uint64
    e_shoff*: uint64
    e_flags*: uint32
    e_ehsize*: uint16
    e_phentsize*: uint16
    e_phnum*: uint16
    e_shenntsize*: uint16
    e_shnum8: uint16
    e_shstrndx*: uint16

  Elf64_Phdr* = object
    p_type*: uint32
    p_offset*: uint32
    p_vaddr*: uint64
    p_paddr*: uint64
    p_filesz*: uint64
    p_memsz*: uint64
    p_flags*: uint64
    p_align*: uint64

  Elf64_Shdr* = object
    sh_name*: uint32
    sh_type*: uint32
    sh_flags*: uint64
    sh_addr*: uint64
    sh_offset*: uint64
    sh_size*: uint64
    sh_link*: uint64
    sh_info*: uint64
    sh_addralign*: uint64
    sh_entsize*: uint64

  Elf64_Dyn_inner_union {.union.} = object
    d_val*: uint64
    d_ptr*: uint64

  Elf64_Dyn* = object
    d_tag*: int64
    d_un*: Elf64_Dyn_inner_union

  Elf64_Rel* = object
    r_offset: uint64
    r_info*: uint64

  Elf64_Rela* = object
    r_offset*: uint64
    r_info*: uint64
    r_addend*: int64


  Elf64_Sym* = object
    st_name*: uint32
    st_info*: cuchar
    st_other*: cuchar
    st_shndx*: uint16
    st_value*: uint64
    st_size*: uint64
