import os, sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import datolite as dt
import json

def analyzer_cli():
  executable = sys.argv[2]
  patch = sys.argv[3]
  assert os.path.exists(executable), "Executable not found"
  assert os.path.exists(patch), "Patch not found"
  dt.assembler.init_assembler(executable)

  dt.Logger.info("Running analysis on {} for {}\n".format(executable, patch.split("/")[-1]))
  for i,patch in enumerate(dt.dpt.load_tester(patch)):
    dt.Logger.info("Patch #{}".format(i))
    for k,v in dt.disassembler.get_disassembler().analyze_sizes(executable, patch).items():
      dt.Logger.info("Function: {} | Start: {} | End: {}".format(k, hex(v[0]), hex(v[1])))
    print("\n\n")

def ghelp():
  print("Datolite - A complete binary patcher")
  print("Usage: datolite (config file is root.dls. No arguments)")
  print("       datolite @analyze [executable] [patch]")
  print("       datolite @help")
  print("\n\n== How To ==")
  print("   No arguments: patches the binary according to the 'root.dls' file")
  print("   @analyze: finds optimal patch locations for a given patch")

def argparse():
  if sys.argv[1] == "@analyze":
    analyzer_cli()
  elif sys.argv[1] in ["-h", "--help", "@help", "help"]:
    ghelp()
  else:
    print("Invalid command")
    ghelp()

def main():
  if len(sys.argv) > 1:
    argparse()
    return

  with open("root.dls", "r") as f:
    config = json.load(f)
  
  assert "executable" in config, "Source file not specified [KEY: executable]"
  assert "patches" in config, "Patches not specified [KEY: patches (array of path)]"

  dt.Patcher(
    config["executable"],
    config["patches"],
    (config["output"] if "output" in config else None),
  ).patch()

if __name__ == "__main__":
  main()