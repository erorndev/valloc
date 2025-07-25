// SPDX-License-Identifier: BSD-3-Clause
/*
Modül adı: mm.c
Açıklama:
  Geliştirilmiş heap allocator implementasyonu.
  malloc, free, calloc, realloc fonksiyonları desteklidir.
  Dinamik bellek havuzu yönetimi ile esnek çalışır.
*/
#include "mm.h"
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>

#define MIN_POOL_SIZE (1024 * 1024)    
#define MAX_POOL_SIZE (128 * 1024 * 1024) 
#define ALIGNMENT 8                   
#define MIN_BLOCK_SIZE 16             

// Bellek pool yapısı
struct mm_pool {
    void *start;
    size_t size;
    struct mm_pool *next;
};

static struct mm_pool *pool_list = NULL;
static struct mm_header *free_list = NULL;
static bool heap_init = false;
static size_t total_allocated = 0;
static size_t total_pools = 0;
pthread_mutex_t heap_lock = PTHREAD_MUTEX_INITIALIZER;

static size_t align_size(size_t size) {
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

static void* get_hint_address(void) {
    // kernel halletsin
    return NULL;
}

static struct mm_pool* create_new_pool(size_t min_size) {
    size_t pool_size = MIN_POOL_SIZE;
    
    while (pool_size < min_size + sizeof(struct mm_header)) {
        pool_size *= 2;
        if (pool_size > MAX_POOL_SIZE) break;
    }
    
    void *pool_mem = mmap(NULL, pool_size, PROT_READ | PROT_WRITE, 
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool_mem == MAP_FAILED) {
        return NULL;
    }
    
    struct mm_pool *new_pool = (struct mm_pool*)pool_mem;
    new_pool->start = pool_mem;
    new_pool->size = pool_size;
    new_pool->next = pool_list;
    pool_list = new_pool;
    
    struct mm_header *header = (struct mm_header*)((char*)pool_mem + sizeof(struct mm_pool));
    header->block_size = pool_size - sizeof(struct mm_pool) - sizeof(struct mm_header);
    header->is_free = true;
    header->next = free_list;
    free_list = header;
    
    total_pools++;
    return new_pool;
}

static void split_block(struct mm_header *block, size_t size) {
    size_t remaining = block->block_size - size;
    
    if (remaining >= sizeof(struct mm_header) + MIN_BLOCK_SIZE) {
        struct mm_header *new_block = (struct mm_header *)((char *)(block + 1) + size);
        new_block->block_size = remaining - sizeof(struct mm_header);
        new_block->is_free = true;
        new_block->next = block->next;
        
        block->block_size = size;
        block->next = new_block;
    }
}

static struct mm_header* find_best_fit(size_t size) {
    struct mm_header *current = free_list;
    struct mm_header *best = NULL;
    size_t best_size = SIZE_MAX;
    
    while (current != NULL) {
        if (current->is_free && current->block_size >= size) {
            if (current->block_size < best_size) {
                best = current;
                best_size = current->block_size;
                
                // Tam uygun boyut bulundu
                if (best_size == size) {
                    break;
                }
            }
        }
        current = current->next;
    }
    
    return best;
}

static void coalesce_free_blocks() {
    struct mm_header *current = free_list;
    
    while (current && current->next) {
        if (current->is_free && current->next->is_free &&
            (char *)current + sizeof(struct mm_header) + current->block_size == (char *)current->next) {
            
            current->block_size += sizeof(struct mm_header) + current->next->block_size;
            current->next = current->next->next;
        } else {
            current = current->next;
        }
    }
}

static bool is_valid_ptr(void *ptr) {
    if (ptr == NULL) return false;
    
    struct mm_pool *pool = pool_list;
    while (pool) {
        char *start = (char*)pool->start + sizeof(struct mm_pool);
        char *end = (char*)pool->start + pool->size;
        
        if ((char*)ptr >= start && (char*)ptr < end) {
            struct mm_header *header = ((struct mm_header *)ptr) - 1;
            return (char*)header >= start && !header->is_free;
        }
        pool = pool->next;
    }
    return false;
}

void *malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    if (size > SIZE_MAX - sizeof(struct mm_header) - ALIGNMENT) {
        errno = ENOMEM;
        return NULL;
    }
    
    size = align_size(size);
    
    pthread_mutex_lock(&heap_lock);
    
    if (!heap_init) {
        if (create_new_pool(size) == NULL) {
            pthread_mutex_unlock(&heap_lock);
            errno = ENOMEM;
            return NULL;
        }
        heap_init = true;
    }
    
    struct mm_header *block = find_best_fit(size);
    
    if (block == NULL) {
        if (create_new_pool(size) == NULL) {
            pthread_mutex_unlock(&heap_lock);
            errno = ENOMEM;
            return NULL;
        }
        block = find_best_fit(size);
    }
    
    if (block != NULL) {
        split_block(block, size);
        block->is_free = false;
        total_allocated += size;
        
        pthread_mutex_unlock(&heap_lock);
        return (void *)(block + 1);
    }
    
    pthread_mutex_unlock(&heap_lock);
    errno = ENOMEM;
    return NULL;
}

void free(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    
    pthread_mutex_lock(&heap_lock);
    
    if (!is_valid_ptr(ptr)) {
        pthread_mutex_unlock(&heap_lock);
        return; 
    }
    
    struct mm_header *header = ((struct mm_header *)ptr) - 1;
    if (header->is_free) {
        pthread_mutex_unlock(&heap_lock);
        return; 
    }
    
    header->is_free = true;
    total_allocated -= header->block_size;
    
    coalesce_free_blocks();
    
    pthread_mutex_unlock(&heap_lock);
}

void *calloc(size_t num, size_t size) {
    if (size != 0 && num > SIZE_MAX / size) {
        errno = ENOMEM;
        return NULL;
    }
    
    size_t total = num * size;
    void *ptr = malloc(total);
    
    if (ptr != NULL) {
        memset(ptr, 0, total);
    }
    
    return ptr;
}

void *realloc(void *ptr, size_t new_size) {
    if (ptr == NULL) {
        return malloc(new_size);
    }
    
    if (new_size == 0) {
        free(ptr);
        return NULL;
    }
    
    pthread_mutex_lock(&heap_lock);
    
    if (!is_valid_ptr(ptr)) {
        pthread_mutex_unlock(&heap_lock);
        errno = EINVAL;
        return NULL;
    }
    
    struct mm_header *header = ((struct mm_header *)ptr) - 1;
    size_t old_size = header->block_size;
    new_size = align_size(new_size);
    
    if (new_size <= old_size) {
        // Block'u böl
        if (old_size - new_size >= sizeof(struct mm_header) + MIN_BLOCK_SIZE) {
            split_block(header, new_size);
            total_allocated -= (old_size - new_size);
        }
        pthread_mutex_unlock(&heap_lock);
        return ptr;
    }
    
    pthread_mutex_unlock(&heap_lock);

    void *new_ptr = malloc(new_size);
    if (new_ptr) {
        memcpy(new_ptr, ptr, old_size);
        free(ptr);
    }
    
    return new_ptr;
}