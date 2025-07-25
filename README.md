```
Custom heap allocator with dynamic memory pools.
This is not meant for production-grade applications,
YAGNI and KISS were used in this project.

Features
* mmap memory pools (min 1MB)
* Best-fit allocation
* Block splitting & merging
* Thread-safe with pthread mutex
* 8-byte alignment

## Build

cmake .
make

## License
BSD 3-Clause
```