import os, sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import datolite as dt
import json

def analyzer_cli():
  executable = sys.argv[2]
  patch = sys.argv[3]
  dt.Logger.cassert(os.path.exists(executable), "Executable not found")
  dt.Logger.cassert(os.path.exists(patch), "Patch not found")
  dt.assembler.init_assembler(executable)

  dt.Logger.info("Running analysis on {} for {}\n".format(executable, patch.split("/")[-1]))
  for i,patch in enumerate(dt.dpt.load_tester(patch)):
    dt.Logger.info("Patch #{}".format(i))
    for k,v in dt.disassembler.get_disassembler().analyze_sizes(executable, patch).items():
      dt.Logger.info("Function: {} | Start: {} | End: {}".format(k, hex(v[0])[2:].upper(), hex(v[1])[2:].upper()))
    print("\n\n")

def patcher_cli():
  with open("root.dls", "r") as f:
    config = json.load(f)
  
  dt.Logger.cassert("executable" in config, "Source file not specified [KEY: executable]")
  dt.Logger.cassert("patches" in config, "Patches not specified [KEY: patches (array of path)]")

  dt.Patcher(
    config["executable"],
    config["patches"],
    (config["output"] if "output" in config else None),
  ).patch()

def list_cli():
  fns = dt.disassembler.get_disassembler().fn_list(sys.argv[2])
  dt.Logger.info("Assuming base address is 0x1000000")
  for k,v in fns.items():
    dt.Logger.info("Function: {} | Start: {} | End: {}".format(k, hex(v[0])[2:].upper(), hex(v[1])[2:].upper()))
  print("\n\n")

def ghelp():
  print("Datolite - A complete binary patcher")
  print("Usage: datolite -patch")
  print("       datolite -analyze [executable] [patch]")
  print("       datolite -list [executable]")
  print("       datolite -help")
  print("\n\n== How To ==")
  print("   -patch: patches the binary according to the 'root.dls' file")
  print("   -analyze: finds optimal patch locations for a given patch")
  print("   -list: List all functions addresses in executable")

def argparse():
  if sys.argv[1] == "-analyze":
    analyzer_cli()
  elif sys.argv[1] == "-patch":
    patcher_cli()
  elif sys.argv[1] == "-list":
    list_cli()
  elif sys.argv[1] in ["-h", "--help", "-help", "help"]:
    ghelp()
  else:
    print("Invalid command")
    ghelp()

def main():
  if len(sys.argv) > 1:
    argparse()
    return
  else:
    ghelp()

if __name__ == "__main__":
  main()