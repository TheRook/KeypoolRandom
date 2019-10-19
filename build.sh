#!/bin/bash
gcc -Wall -g main.c -Ilinux -Ilinux/include -Ilinux/include/uapi -Ilinux/arch/ia64/include/uapi -Ilinux/arch/ia64/include -Ilinux/tools/arch/ia64/include -Ilinux/tools/arch/ia64/include/uapi -IWjCryptLib/lib -L linux linux/include WjCryptLib/lib/ ./WjCryptLib/lib/WjCryptLib_AesOfb.c ./WjCryptLib/lib/WjCryptLib_Aes.c -o poolrand -ferror-limit=3 -w
