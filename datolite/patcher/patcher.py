from os.path import isfile,getsize
from shutil import copy2
import mmap

from datolite.logger import Logger
from datolite.parser import dpt, Patch
from datolite.assembler import init_assembler

class Patcher():
  def __init__(self, src: str, patches: list[str], output: str=None):
    self.src = src
    self.patches = patches
    self.output = output
    if not self.output:
      splet = self.src.split("/")
      splet[-1] = "patched." + splet[-1]
      self.output = "/".join(splet)
    
    Logger.cassert(isfile(self.src), "Source file does not exist")
    Logger.cassert(getsize(self.src) > 0, "Source file is empty")
    Logger.cassert(self.src != self.output, "Source file and output file are the same")
    for patch in self.patches:
      Logger.cassert(isfile(patch), "Patch file {} does not exist".format(patch))
      Logger.cassert(getsize(patch) > 0, "Patch file {} is empty".format(patch))
      Logger.cassert(patch.endswith(".dpt"), "Patch file {} is not a .dpt file".format(patch))
    
    init_assembler(self.src)
    
  def patch(self):
    copy2(self.src, self.output)
    with open(self.output, 'r+b') as f:
      mm = mmap.mmap(f.fileno(), 0)

      for patch_file in self.patches:
        Logger.info("Applying patches from {}".format(patch_file.split("/")[-1]))
        f_patches: list[Patch] = dpt.load(patch_file)

        for patch in f_patches:
          Logger.debug(
            "(PRE-PATCH) Address {} small dump: {}".format(hex(patch.start), mm[patch.file_offset:patch.file_offset+8].hex(sep=' '))
          )
          mm[patch.file_offset:patch.file_offset+len(patch.dump)] = patch.dump
          Logger.info("Patched {} bytes".format(hex(len(patch.dump))))
          Logger.debug(
            "(POST-PATCH) Address {} small dump: {}".format(hex(patch.start), mm[patch.file_offset:patch.file_offset+8].hex(sep=' '))
          )
          print("\n")
        print("\n")
      mm.flush()