import os, subprocess

class Disassembler():
  def __init__(self):
    assert subprocess.run(["gcc", "--version"], stdout=subprocess.DEVNULL).returncode == 0, "GCC is not installed"
    assert subprocess.run(["objdump", "--version"], stdout=subprocess.DEVNULL).returncode == 0, "objdump is not installed"
  
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
        

  def ccde(self, path: str, function: str) -> str:
    output = path + ".o"
    subprocess.run(
      ["gcc", "-c", path, "-o", output],
      stdout=subprocess.DEVNULL
    )
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