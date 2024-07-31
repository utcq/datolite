import subprocess

from datolite.logger import Logger

class Disassembler():
  def __init__(self):
    Logger.cassert(subprocess.run(["gcc", "--version"], stdout=subprocess.DEVNULL).returncode == 0, "GCC is not installed")
    Logger.cassert(subprocess.run(["objdump", "--version"], stdout=subprocess.DEVNULL).returncode == 0, "objdump is not installed")
    Logger.info("Tools present, Initialized disassembler")
  
  def __extract_function(self, cmd_output: str, fn_name: str) -> str:
    result = []
    is_fn = False
    for line in cmd_output.split("\n"):
      if line.endswith(f"<{fn_name}>:"):
        result.append(line)
        is_fn = True
      elif is_fn:
        if line.startswith(" ") and line != "":
          result.append(line)
        else:
          break
    return "\n".join(result)

  def __extract_encoded(self, dump: str) -> str:
    result = []
    for line in dump.split("\n"):
      if line.startswith(" "):
        result.append(line.split("\t")[1])
    return ' '.join(
      list(map(lambda x: x.strip(), (result)))
    ).upper()

  def __fn_lister(self, cmd_output: str) -> list[tuple[int, str]]:
    result = []
    for line in cmd_output.split("\n"):
      if line.endswith(">:"):
        result.append(
          (int(line.split(" ")[0],16),
          line.split(" ")[-1][1:-2])
        )
    return result

  def fn_list(self, exe_path: str) -> dict[str, tuple[int, int]]:
    disassembly = subprocess.run(
      ["objdump", "-d", exe_path],
      capture_output=True,
      text=True
    ).stdout

    functions = self.__fn_lister(disassembly)
    result = {}
    for fn in functions:
      dump = self.__extract_function(disassembly, fn[1])
      encoded = self.__extract_encoded(dump)
      fn = (fn[0]+0x1000000,fn[1])
      end = fn[0] + len(encoded.split(" "))
      result[fn[1]] = (fn[0],end)
    return result
  
  
  def analyze_sizes(self, exe_path: str, patch) -> dict[str, tuple[int, int]]:
    disassembly = subprocess.run(
      ["objdump", "-d", exe_path],
      capture_output=True,
      text=True
    ).stdout

    functions = self.__fn_lister(disassembly)
    result = {}
    for fn in functions:
      dump = self.__extract_function(disassembly, fn[1])
      encoded = self.__extract_encoded(dump)
      fn = (fn[0]+patch.base,fn[1])
      end = fn[0] + len(encoded.split(" "))
      if len(encoded.split(" ")) >= len(patch.dump):
        result[fn[1]] = (fn[0],end)
    return result

  def ccde(self, path: str, function: str) -> str:
    output = path + ".o"
    subprocess.run(
      ["gcc", "-c", path, "-o", output],
      stdout=subprocess.DEVNULL
    )
    Logger.info("Compiled C Source: {}".format(path))
    disassembly = subprocess.run(
      ["objdump", "-d", output],
      capture_output=True,
      text=True
    ).stdout

    dump = self.__extract_function(disassembly, function)
    return self.__extract_encoded(dump)

global disassembler_instance
disassembler_instance = None

def get_disassembler():
  global disassembler_instance
  if not disassembler_instance:
    disassembler_instance = Disassembler()
  return disassembler_instance