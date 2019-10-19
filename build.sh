#!/bin/bash
gcc -Wall -g main.c -IWjCryptLib/lib ./WjCryptLib/lib/WjCryptLib_AesOfb.c ./WjCryptLib/lib/WjCryptLib_Aes.c -o keypool -ferror-limit=3 -w
