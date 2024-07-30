import lief
from keystone import *

def get_arch(path: str) -> tuple[int, int]:
  binary = lief.parse(path)
  if binary is None:
      raise ValueError("Unable to parse the file. Ensure it is a valid executable.")

  if lief.is_elf(path):
    if binary.header.machine_type == lief.ELF.ARCH.X86_64:
        return KS_ARCH_X86, KS_MODE_64
    elif binary.header.machine_type == lief.ELF.ARCH.X86:
        return KS_ARCH_X86, KS_MODE_32
    elif binary.header.machine_type == lief.ELF.ARCH.ARM:
        return KS_ARCH_ARM, KS_MODE_32
    elif binary.header.machine_type == lief.ELF.ARCH.AARCH64:
        return KS_ARCH_ARM64, KS_MODE_64
    elif binary.header.machine_type == lief.ELF.ARCH.MIPS:
        return KS_ARCH_MIPS, KS_MODE_32
    else:
        raise ValueError("Unsupported ELF architecture.")

  elif lief.is_pe(path):
    if binary.header.machine == lief.PE.MACHINE_TYPES.AMD64:
        return KS_ARCH_X86, KS_MODE_64
    elif binary.header.machine == lief.PE.MACHINE_TYPES.I386:
        return KS_ARCH_X86, KS_MODE_32
    elif binary.header.machine == lief.PE.MACHINE_TYPES.ARM:
        return KS_ARCH_ARM, KS_MODE_32
    elif binary.header.machine == lief.PE.MACHINE_TYPES.ARM64:
        return KS_ARCH_ARM64, KS_MODE_64
    else:
        raise ValueError("Unsupported PE architecture.")
  
  else:
      raise ValueError("Unsupported executable format.")

class Assembler():
  def __init__(self, src_path: str):
    arch, mode = get_arch(src_path)
    self.ks = Ks(arch, mode)


global assembler_instance

def init_assembler(src_path: str):
  global assembler_instance
  assembler_instance = Assembler(src_path)

def get_assembler() -> Assembler:
  return assembler_instance