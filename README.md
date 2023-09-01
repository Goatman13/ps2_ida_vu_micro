# ps2_ida_vu_micro
* Plugin that tries to find and disassembly vu microcode in ps2 executables.

## Usage
* Throw .py file into IDA plugins directory
* Push F10 to disassemble selected/marked lines
* Push Alt + Shift + 5 on VIF MPG (0x4AXXXXXX) command to try auto disassemble all known VU code at once.

## Bugs
* Plugin is a mess, but can work here and there.
* Branching target is broken in many situations. Like when program try to branch below 0x0, or above 0xFFF/0x3FFF. Also when there is vif command in the middle more advanced than MPG/Unpack/Nop. So when branch target look suspicious, it is most likely worng.
* Probably many more, it just implement basics so i don't need to run 2000s ps2dis to see vu disassembly.

## Requirements
* Dunno. Run fine in IDA 7.5 with python 3 (so probably python 3).

## Preview
![preview](https://user-images.githubusercontent.com/101417270/202868009-e89f557e-d267-40b8-8ff5-433314c5a2e1.jpg)
