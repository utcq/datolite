import os, sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import datolite as dt
import json

def main():
  with open("root.dls", "r") as f:
    config = json.load(f)
  
  assert "executable" in config, "Source file not specified [KEY: executable]"
  assert "patches" in config, "Patches not specified [KEY: patches (array of path)]"
  
  dt.Patcher(
    config["executable"],
    config["patches"],
    (config["output"] if "output" in config else None),
    (config["filler"] if "filler" in config else 0x90)
  ).patch()

if __name__ == "__main__":
  main()