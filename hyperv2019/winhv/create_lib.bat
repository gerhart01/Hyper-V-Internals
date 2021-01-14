dumpbin /exports winhv.sys > tmp.txt
lib.exe /def:winhv.def /OUT:winhv.lib /machine:x86 