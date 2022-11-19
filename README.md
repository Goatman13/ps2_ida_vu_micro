# ps2_ida_vu_micro
* Script that tries to find and disassembly vu microcode in ps2 executables.

## Usage
* Select script in ida file --> script file

## Bugs
* Script is a mess, but can work here and there.
* When default search fail you can uncomment "manual" mode, and specify where vu code is in mark_code function call. 
* Branching target is broken in many situations. Like when program try to branch below 0x0, or above 0xFFF/0x3FFF. Also when there is vif command in the middle more advanced than 0x4A MPG. So when branch target look suspicious, it is most likely worng.
* Probably many more, it just implement basics so i don't need to run 2000s ps2dis to see vu disassembly.

## Requirements
* Dunno. Run fine in IDA 7.5 with python 3.

Don't bother to create issue, prs are welcome.
