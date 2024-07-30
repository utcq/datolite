from os.path import isfile,getsize
from shutil import copy2
import mmap

from datolite.logger import Logger
from datolite.parser import dpt, Patch

class Patcher():
  def __init__(self, src: str, patches: list[str], output: str=None):
    self.src = src
    self.patches = patches
    self.output = output
    if not self.output:
      splet = self.src.split("/")
    
    assert isfile(self.src), "Source file does not exist"
    assert getsize(self.src) > 0, "Source file is empty"
    assert self.src != self.output, "Source file and output file are the same"
    for patch in self.patches:
      assert isfile(patch), format("Patch file {} does not exist", patch)
      assert getsize(patch) > 0, format("Patch file {} is empty", patch)
      assert patch.endswith(".dpt"), format("Patch file {} is not a .dpt file", patch)
    
  def patch(self):
    copy2(self.src, self.output)
    with open(self.output, 'r+b') as f:
      mm = mmap.mmap(f.fileno(), 0)

      for patch_file in self.patches:
        Logger.info("Applying patches from {}".format(patch_file.split("/")[-1]))
        f_patches: list[Patch] = dpt.load(patch_file)

        for patch in f_patches:
          Logger.debug(
            "(PRE-PATCH) Address {} small dump: {}".format(patch.start, mm[patch.file_offset:patch.file_offset+8].hex(sep=' '))
          )
          Logger.info("Patching {} bytes".format(hex(len(patch.dump))))
          mm[patch.file_offset:patch.file_offset+len(patch.dump)] = patch.dump
          Logger.debug(
            "(POST-PATCH) Address {} small dump: {}".format(patch.start, mm[patch.file_offset:patch.file_offset+8].hex(sep=' '))
          )
          print("\n\n")
        print("\n")
      mm.flush()