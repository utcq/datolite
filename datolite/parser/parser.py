import re

class Patch:
  base: int
  offset: int
  start: int
  end: int
  file_offset: int
  dump: bytearray

class dpt:
  def __dump_reader(repr: str) -> bytearray:
    return bytearray(
      map(lambda x: int(x, 16), repr.strip().split(" "))
    )

  def __syntax_solver(hexdump: str) -> bytearray:
    matches = re.findall(r"[0-9a-z-A-Z]{2}[\s+]?\*[\s+]?[0-9a-zA-Z]+", hexdump, re.MULTILINE)
    for match in matches:
      byte_t = match.split("*")[0].strip() + " "
      mul = eval(match.split("*")[1].strip())
      res = (byte_t*mul)[:-1]
      hexdump = hexdump.replace(match, res)
    
    matches = re.findall(r"[\s]+\"[0-9a-zA-Z +-_*'\s]+\"", hexdump, re.MULTILINE)
    for match in matches:
      hexdump = hexdump.replace(match, "")
    
    return dpt.__dump_reader(hexdump)

  def __build_biunary(patch: Patch):
    nop_filler = (patch.end - patch.start) - len(patch.dump)
    assert nop_filler >= 0, "Patch is too big"
    patch.dump.extend([0x90]*nop_filler)

  def load(path: str) -> list[Patch]:
    tables = open(path, 'r').read().split("\n\n---\n\n")
    patches = []
    for table in tables:
      header = table.split("\n")[0].split(" ")
      hexdump = ' '.join(table.split("\n")[2:])
      
      patch = Patch()
      patch.base, patch.offset, patch.start, patch.end = (
        int(header[0], 16),
        int(header[1], 16),
        int(header[2].split(":")[0], 16),
        int(header[2].split(":")[1], 16)
      )

      patch.file_offset = patch.start - patch.base - patch.offset
      patch.dump = dpt.__syntax_solver(hexdump)
      dpt.__build_biunary(patch)
    return patches
