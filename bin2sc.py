#!/usr/bin/env python3
import sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: {} file.bin c|cs".format(sys.argv[0]))
        sys.exit(0)

    if sys.argv[2] == "c":
        # for c shellcode
        shellcode = "\""
        ctr = 1
        maxlen = 15

        with open(sys.argv[1], "rb") as f:
            bytes = f.read()
            for b in bytes:
                shellcode += "\\x" + format(b, "02x")
                if ctr == maxlen:
                    shellcode += "\" \n\""
                    ctr = 0
                ctr += 1
        shellcode += "\""
        print(shellcode)

    else:
        # for cs shellcode
        shellcode = ""
        ctr = 1
        maxlen = 15
        
        with open(sys.argv[1], "rb") as f:
            bytes = f.read()
            for b in bytes:
                shellcode += "0x" + format(b, "02x") + ","
                if ctr == maxlen:
                    shellcode += "\n"
                    ctr = 0
                ctr += 1

        print(shellcode)
