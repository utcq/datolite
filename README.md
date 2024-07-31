# Datolite

> **A modular binary patcher**

---

## Patch File Structure (.dpt)

```r
BASE HIDDEN_OFFSET START:END (FILLER?)

00 01 02 03 04 05 06 07 08
```

(Single patch file)

**EVERY VALUE IN THE FILE IS HEXADECIMAL**

```r
BASE HIDDEN_OFFSET START:END (FILLER?)

01 02 03 04 05 06 07 08

---

BASE HIDDEN_OFFSET START:END (FILLER?)

09 0A 0B 0C 0D 0E 0F 10
```

(Multi patch file)

```r
BASE HIDDEN_OFFSET START:END (FILLER?)

$ data/message.txt

```

(Including file content as bytes)

```r
BASE HIDDEN_OFFSET START:END (FILLER?)

09 0A 0B 0C 0D 0E 0F 10
>> mov rax, 0x10
```

(Instruction encoding at patch time, the architecutre is detected from the source file)

```r
BASE HIDDEN_OFFSET START:END (FILLER?)

c=> testing/test.c:main
```

(Compilation, disassembly and encoding of a C file at patch-time, format `path:function`)

#### ! SPACES AND DASHES ARE IMPORTANT AS THERE ISN'T A LEXER SO THE PARSING IS DONE WITH REGEX!

---

### Explaination

**BASE** = _Virtual Offset, `0x100000` by convention_

**HIDDEN_OFFSET** = _Win32/64 executables have a `0xC00` offset from base_

**START** = _Start address of the VIRTUAL memory region to map (gather via disassembler)_

**END** = _End address of the VIRTUAL memory region to map (gather via disassembler)_

**FILLER** = _Optional value that is going to be put to fill the region, `0x90` is the default as it is NOP instruction_

**(In case of instructions the end is always the address of the instruction after the region)**

---

## Root Config File (.dls)

When patching an executable without scripting the process you have to use `root.dls`

**Just JSON without comments**

```json
{
  "executable": "testing/test",
  "output": "patched_test",
  "patches": ["testing/stringPatch.dpt"]
}
```

**(Output is optional, if not set it will be `path/patched.filename`)**
