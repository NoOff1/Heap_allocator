# Heap_allocator
Custom Heap allocator written in C.

# Overview
A simple and interactive heap memory allocator written in C. This project demonstrates how dynamic memory allocation works under the hood — implementing custom versions of `malloc`, `calloc`, `realloc`, and `free` using a manually managed memory region.

# Features
- Custom `malloc`, `calloc`, `realloc`, and `free`
- Block splitting and coalescing for efficient memory usage
- Hardened against:
  - Integer overflows in `calloc`
  - Double frees
  - Misaligned memory access
  - Unsafe CLI input
- Interactive CLI to test and visualize allocations
- Simple free list allocator with minimal dependencies

# How it works
malloc(size):
Scans the free list for a large enough free block.
Splits the block if it's too big.
Marks it as used and returns a pointer to the memory after the header.

calloc(n, size):
Multiplies n * size with overflow check.
Allocates memory and zeroes it out with memset.

realloc(ptr, new_size):
If the current block is large enough, returns it as-is.
Otherwise, allocates a new block, copies data, and frees the old block.

free(ptr):
Marks the block as free.
Tries to coalesce it with adjacent free blocks to reduce fragmentation.
Detects double frees and prints a warning.

# CLI commands
malloc SIZE	- Allocates SIZE bytes of memory
calloc NUM SIZE	- Allocates and zeroes NUM blocks of SIZE
realloc INDEX SIZE	- Changes size of memory at INDEX to SIZE
free INDEX	- Frees the memory at given pointer index
print	- Shows the current state of heap and allocations
exit	- Exits the program
