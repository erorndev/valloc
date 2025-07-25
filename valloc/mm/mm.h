// SPDX-License-Identifier: BSD-3-Clause
/*
Modül adı: mm.h
Açıklama:
  Geliştirilmiş heap allocator header dosyası.
  Standard malloc interface'i ve ek debug fonksiyonları.
*/
#ifndef MM_H
#define MM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

struct mm_header {
    size_t block_size;          
    bool is_free;               
    struct mm_header *next;     
};

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t num, size_t size);
void *realloc(void *ptr, size_t new_size);

#endif // MM_H