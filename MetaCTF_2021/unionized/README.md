# Unionized

A union type confusion heap challenge at MetaCTF CyberGames 2021.

**Summary**: Use union confusion between char and string (pointer) to overwrite
function pointers on the heap. ASLR can be brute forced by writing lower 2 bytes
and guessing the top 4 bits.

## Challenge description

> Why didn't anyone tell me about the magic of Unionized when I first started
> programming? I would have saved so much memory with these nifty things, don't
> you think? Here try my application and tell me what you think
> host.cg21.metaproblems.com:3150

### Files:

- [unionized_Release.tar.gz](unionized_Release.tar.gz): (includes challenge
  binary and source code)

## First steps

At first, this seems like a typical heap note challenge. We can add, edit, and
remove objects.

```
What would you like to do?
1. Create new object
2. Display objects
3. Edit Object
4. Delete Object
5. Exit

```

However, they challenge title hints at an exploit involving union, so let's look
for that. The user can create and edit objects. Objects are stored in a struct
in a linked list and have a pointer to a function for printing. There is a `win`
function that pops a shell for us.

Here is the full struct:
```c
struct created{
	int type;
	int size;

	union Variable {
		char * string;
		int integer;
		long long long_boi;
		char character;
	} variable;

	void (*print)();
	struct created *next;
};
```

## The vulnerability

The program lets us set the input an integer, long, char, or string. The
behavior for reading in an int, long, and char are all very similar. Here is an
excerpt for reading in an int:

```c
printf("What is your value:\n");
scanf("%d", &tmp->variable.integer);
tmp->type = 2;
tmp->print = display_int;
```

Reading in a string is a bit different. First the program asks the user for the
length, then it `mallocs` a region of that size (but only if the size is larger
than the current size). Finally, it reads in data using `read`:

```c
read(0, tmp->variable.string, tmp->size);
tmp->type = 1;
tmp->print = display_string;
```

The vulnerability lies in not `malloc`ing a new chunk every time a string is
read in. This means we can modify the address at `tmp->variable` and then write
to it by converting it back to a string.

## Exploit plan

The general plan is to create a string object, modify it to point to a
function pointer next to it on the heap, and then overwrite the pointer so that
it points to `win`.

We can do this by creating a string, changing its type to a character (to modify
the lowest byte to point to a function pointer in the struct), and then change
it back to a string and writing the address to `win`.

## Heap details

Here I've created two objects with strings, "AAAA" and "BBBB". Let's take a closer
look at what's being stored on the heap:

```
(gdb) x/20gx 0x5555555592a0
0x5555555592a0:   [0] 0x0000000400000001   [1] 0x00005555555592d0
0x5555555592b0:       0x0000555555555226       0x00005555555592f0
0x5555555592c0:       0x0000000000000000       0x0000000000000021
0x5555555592d0:   [2] 0x0000000061616161       0x0000000000000000
0x5555555592e0:       0x0000000000000000       0x0000000000000031
0x5555555592f0:       0x0000000400000001       0x0000555555559320
0x555555559300:   [3] 0x0000555555555226       0x0000000000000000
0x555555559310:       0x0000000000000000       0x0000000000000021
0x555555559320:       0x0000000062626262       0x0000000000000000
0x555555559330:       0x0000000000000000       0x0000000000020cd1
```

The `created` struct starts at `[0]` and holds the type, size, Variable union,
`print` function pointer, and a pointer to the next struct (they are stored in a
linked list).

We can modify the string pointer at `[1]` (which currently points to the string
at `[2]`) to point to `[3]` (the `print` function of the next item). Here we can
do that by changing the last byte to `00`. However, this is dependent on libc
versions, so this may not work with the server's libc. Since heap chunks are
8-byte aligned (on 64-bit systems), we can brute force all 256/8 = 32
possibilities. Then we can overwrite the pointer to the `win` function. However,
we have ASLR to deal with.

## Brute forcing ASLR

The `win` function differs from the `display_*` functions by several hundred
bytes, so we need to overwrite the lower 2 bytes.

```
(gdb) x/i win
   0x555555555680 <win>:        push   rbp
(gdb) x/i display_character
   0x555555555299 <display_character>:  push   rbp
(gdb) x/i display_int
   0x555555555245 <display_int>:        push   rbp
(gdb) x/i display_long
   0x55555555526e <display_long>:       push   rbp
(gdb) x/i display_string
   0x555555555226 <display_string>:     push   rbp
(gdb)
```

Only the lowest 12 bits (3 hexadecimal digits) are preserved when the address is
shuffled. That means if we overwrite the lower 2 bytes (or 16 bits), we don't
know the 4 highest bits. Since 4 bits only has 16 possibilities, we can just
brute force this to bypass ASLR.

## Full exploit code

See [solve.py](solve.py)
