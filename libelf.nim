import posix, pegs, strutils, ../ptrace/ptrace/ptrace

include private/elf32
include private/elf64
include private/types
include private/utils

let
  freeSpaceEntry = peg(r"{\w+}'-'(\w+)\s[rwxp-]+\s\d+\s'00:00'")
  elfHeaderAddress: clong = 0x08048000

  ehdrLen = sizeof(Elf_Ehdr)
  phdrLen = sizeof(Elf_Phdr)
  shdrLen = sizeof(Elf_Shdr)
  dynLen = sizeof(Elf_Dyn)
  symLen = sizeof(Elf_Sym)

proc getFreeSpaceAddr*(p: int): int =
  var
    fp: File
    path = "/proc/$#/maps" % $p
    line: string

  fp = open(path, fmRead)
  if fp.isNil:
    raise newException(IOError, "Unable to open $# for reading" % path)

  while not endOfFile(fp):
    line = readLine(fp)
    echo line
    if line =~ freeSpaceEntry:
      result = parseHexInt(matches[0])
      break
  close(fp)

proc getLinkMap*(p: int): LinkMap =
  var
    ehdr: Elf_Ehdr
    phdr: Elf_Phdr
    dyn: Elf_Dyn
    got: cuint
    phdr_addr, dyn_addr, map_addr: clong
  attach(p)
  getData(p, elfHeaderAddress, addr ehdr, ehdrLen)
  phdr_addr = elfHeaderAddress + ehdr.e_phoff.clong

  getData(p, phdr_addr, addr phdr, phdrLen)
  while phdr.p_type != PT_DYNAMIC:
    phdr_addr.inc(phdrLen)
    getData(p, phdr_addr, addr phdr, phdrLen)

  getData(p, phdr.p_vaddr.clong, addr dyn, dynLen)
  dyn_addr = phdr.p_vaddr.clong
  while dyn.d_tag != DT_PLTGOT:
    dyn_addr.inc(dynLen)
    getData(p, dyn_addr, addr dyn, dynLen)

  got = dyn.d_un.d_ptr + 4
  getData(p, got.clong, addr map_addr, sizeof(map_addr))
  getData(p, map_addr, addr result, sizeof(LinkMap))
  discard detach(p)


proc findProcMaps(p: int): seq[ProcMap] =
  result = @[]
  var
    mapPath, exePath, line: string
    fp: File
    procMaps: seq[ProcMap] = @[]
  mapPath = "/proc/$#/maps" % $p
  exePath = "/proc/$#/exe" % $p


  fp = open(mapPath, fmRead)
  if fp.isNil:
    raise newException(IOError, "Can not open procmaps file: $#")

  while not endOfFile(fp):
    line = readLine(fp)
    var pm: ProcMap
    if parseProcmapEntry(pm, exePath, line):
      result.add(pm)
  close(fp)

proc loadExternalSymbols*(p: int) =
  var
    ehdr: Elf_Ehdr

  var procMaps = findProcMaps(p)

  var f: File
  for pm in procMaps:
    if pm.fileType != PROCMAPS_FILETYPE_LIB:
      continue

    f = open(pm.path, fmRead)
    getData(f, addr ehdr, 0, ehdrLen)
    echo pm.path
    echo ehdr.e_phoff
    #close(f)


proc getSection*(p, idx: int): Elf_Shdr =
  var
    ehdr: Elf_Ehdr
    shdr_addr: clong

  getData(p, elfHeaderAddress, addr ehdr, ehdrLen)

  shdr_addr = elfHeaderAddress + ehdr.e_shoff.clong + clong(idx * symLen)
  getData(p, shdr_addr, addr result, symLen)


proc getSection*(p: int, strtab: cuint, name: string): tuple[address: clong, shdr: Elf_Shdr] =
  var
    ehdr: Elf_Ehdr
    shdr: Elf_Shdr
    shdr_addr: clong
    strtab_addr: cuint
    count: int

  getData(p, elfHeaderAddress, addr ehdr, ehdrLen)

  strtab_addr =  ehdr.e_shoff.cuint + cuint(ehdr.e_shstrndx.int * sizeof(Elf_Shdr))
  echo strtab_addr - strtab, ", ", ehdr.e_shoff
  echo strtab, ", ", toHex(strtab.int, 8), ", ", strtab_addr, ", ", toHex(strtab_addr.int, 8)
  assert strtab == strtab_addr

  for i in 0..ehdr.e_shnum:
    shdr_addr = elfHeaderAddress + ehdr.e_shoff.clong + clong(i * ehdr.e_shentsize)
    echo "shdr_addr ", shdr_addr, ", ", toHex(shdr_addr.int, 8)
    getData(p, shdr_addr, addr shdr, sizeof(shdr))
    echo shdr
    #echo getString(p, clong(strtab + shdr.sh_name))



proc findSym*(p: int, map: LinkMap, name: string, typ: int): culong =
  result = 0
  var
    dyn: Elf_Dyn
    sym: Elf_Sym
    sym_addr, strtab_addr: cuint
    dyn_addr: int
    shdr: Elf_Shdr
    r_debug: RDebug
    lm: LinkMap

  attach(p)

  dyn_addr = cast[clong](map.l_ld)
  getData(p, dyn_addr, addr dyn, dynLen)
  while dyn.d_tag != DT_NULL:
    if dyn.d_tag == DT_STRTAB:
      echo "STRTAB"
      strtab_addr = dyn.d_un.d_ptr
    elif dyn.d_tag == DT_SYMTAB:
      sym_addr = dyn.d_un.d_ptr
    elif dyn.d_tag == DT_DEBUG:
      echo "DEBUG ", dyn.d_un.d_val

      getData(p, dyn.d_un.d_val, addr r_debug, sizeof(RDebug))
      echo "r_version: ", r_debug.r_version
      echo "r_ldbase: ", r_debug.r_ldbase
      #getData(p, cast[clong](r_debug.r_map), addr lm, sizeof(LinkMap))
      lm = r_debug.r_map[]
      while true:
        echo lm.l_addr
        if lm.l_name != nil:
          echo lm.l_name
        else:
          echo "nil"

        if lm.l_next == nil:
          break
        lm = lm.l_next[]
    dyn_addr.inc(dynLen)
    getData(p, dyn_addr, addr dyn, dynLen)


  dyn_addr = cast[clong](map.l_ld)
  getData(p, dyn_addr, addr dyn, dynLen)
  while dyn.d_tag != DT_NULL:
    if dyn.d_tag == DT_NEEDED:
      echo getString(p, clong(strtab_addr + dyn.d_un.d_ptr))

    dyn_addr.inc(dynLen)
    getData(p, dyn_addr, addr dyn, dynLen)

  while true:
    sym_addr.inc(symLen) # skip first entry
    getData(p, sym_addr.clong, addr sym, symLen)

    if sym.st_name == STN_UNDEF:
      break
    if sym.st_name.int > 0x100_000:
      break
    echo name, ", ", getString(p, clong(strtab_addr + sym.st_name)), ", ", sym.st_value, ", ", toHex(sym.st_value.int, 8)
    if (sym.st_info.int and 0xf) == typ and name == getString(p, clong(strtab_addr + sym.st_name)):
      if sym.st_shndx == SHN_UNDEF:
        discard
        #shdr = getSection(p, sym.st)
      elif sym.st_shndx == SHN_ABS:
        result = sym.st_value
      else:
        #shdr = getSection(p, sym->st_shndx)
        result = 0

      echo "Found ", result
        #return sym.st_value

  discard detach(p)


when isMainModule:
  import os

  let pid = parseInt(paramStr(1))
  var map = getLinkMap(pid)
  #loadExternalSymbols(pid)
  echo findSym(pid, map, "printf", STT_FUNC)
