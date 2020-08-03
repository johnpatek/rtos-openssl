/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include "internal/cryptlib.h"
#include "crypto/cryptlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <openssl/crypto.h>
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
# include <execinfo.h>
#endif

/*
 * the following pointers may be changed as long as 'allow_customize' is set
 */
static int allow_customize = 1;

static void *(*malloc_impl)(size_t, const char *, int)
    = CRYPTO_malloc;
static void *(*realloc_impl)(void *, size_t, const char *, int)
    = CRYPTO_realloc;
static void (*free_impl)(void *, const char *, int)
    = CRYPTO_free;

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
# include "internal/tsan_assist.h"

static TSAN_QUALIFIER int malloc_count;
static TSAN_QUALIFIER int realloc_count;
static TSAN_QUALIFIER int free_count;

# define INCREMENT(x) tsan_counter(&(x))

static char *md_failstring;
static long md_count;
static int md_fail_percent = 0;
static int md_tracefd = -1;
static int call_malloc_debug = 1;

static void parseit(void);
static int shouldfail(void);

# define FAILTEST() if (shouldfail()) return NULL

#else
static int call_malloc_debug = 0;

# define INCREMENT(x) /* empty */
# define FAILTEST() /* empty */
#endif

int CRYPTO_set_mem_functions(
        void *(*m)(size_t, const char *, int),
        void *(*r)(void *, size_t, const char *, int),
        void (*f)(void *, const char *, int))
{
    if (!allow_customize)
        return 0;
    if (m)
        malloc_impl = m;
    if (r)
        realloc_impl = r;
    if (f)
        free_impl = f;
    return 1;
}

int CRYPTO_set_mem_debug(int flag)
{
    if (!allow_customize)
        return 0;
    call_malloc_debug = flag;
    return 1;
}

void CRYPTO_get_mem_functions(
        void *(**m)(size_t, const char *, int),
        void *(**r)(void *, size_t, const char *, int),
        void (**f)(void *, const char *, int))
{
    if (m != NULL)
        *m = malloc_impl;
    if (r != NULL)
        *r = realloc_impl;
    if (f != NULL)
        *f = free_impl;
}

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
void CRYPTO_get_alloc_counts(int *mcount, int *rcount, int *fcount)
{
    if (mcount != NULL)
        *mcount = tsan_load(&malloc_count);
    if (rcount != NULL)
        *rcount = tsan_load(&realloc_count);
    if (fcount != NULL)
        *fcount = tsan_load(&free_count);
}

/*
 * Parse a "malloc failure spec" string.  This likes like a set of fields
 * separated by semicolons.  Each field has a count and an optional failure
 * percentage.  For example:
 *          100@0;100@25;0@0
 *    or    100;100@25;0
 * This means 100 mallocs succeed, then next 100 fail 25% of the time, and
 * all remaining (count is zero) succeed.
 */
static void parseit(void)
{
    char *semi = strchr(md_failstring, ';');
    char *atsign;

    if (semi != NULL)
        *semi++ = '\0';

    /* Get the count (atol will stop at the @ if there), and percentage */
    md_count = atol(md_failstring);
    atsign = strchr(md_failstring, '@');
    md_fail_percent = atsign == NULL ? 0 : atoi(atsign + 1);

    if (semi != NULL)
        md_failstring = semi;
}

/*
 * Windows doesn't have random(), but it has rand()
 * Some rand() implementations aren't good, but we're not
 * dealing with secure randomness here.
 */
# ifdef _WIN32
#  define random() rand()
# endif
/*
 * See if the current malloc should fail.
 */
static int shouldfail(void)
{
    int roll = (int)(random() % 100);
    int shoulditfail = roll < md_fail_percent;
# ifndef _WIN32
/* suppressed on Windows as POSIX-like file descriptors are non-inheritable */
    int len;
    char buff[80];

    if (md_tracefd > 0) {
        BIO_snprintf(buff, sizeof(buff),
                     "%c C%ld %%%d R%d\n",
                     shoulditfail ? '-' : '+', md_count, md_fail_percent, roll);
        len = strlen(buff);
        if (write(md_tracefd, buff, len) != len)
            perror("shouldfail write failed");
#  ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
        if (shoulditfail) {
            void *addrs[30];
            int num = backtrace(addrs, OSSL_NELEM(addrs));

            backtrace_symbols_fd(addrs, num, md_tracefd);
        }
#  endif
    }
# endif

    if (md_count) {
        /* If we used up this one, go to the next. */
        if (--md_count == 0)
            parseit();
    }

    return shoulditfail;
}

void ossl_malloc_setup_failures(void)
{
    const char *cp = getenv("OPENSSL_MALLOC_FAILURES");

    if (cp != NULL && (md_failstring = strdup(cp)) != NULL)
        parseit();
    if ((cp = getenv("OPENSSL_MALLOC_FD")) != NULL)
        md_tracefd = atoi(cp);
}
#endif

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    void *ret = NULL;

    INCREMENT(malloc_count);
    if (malloc_impl != NULL && malloc_impl != CRYPTO_malloc)
        return malloc_impl(num, file, line);

    if (num == 0)
        return NULL;

    FAILTEST();
    if (allow_customize) {
        /*
         * Disallow customization after the first allocation. We only set this
         * if necessary to avoid a store to the same cache line on every
         * allocation.
         */
        allow_customize = 0;
    }
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (call_malloc_debug) {
        CRYPTO_mem_debug_malloc(NULL, num, 0, file, line);
        ret = malloc(num);
        CRYPTO_mem_debug_malloc(ret, num, 1, file, line);
    } else {
        ret = malloc(num);
    }
#else
    (void)(file); (void)(line);
    ret = rtos_malloc(num);
#endif

    return ret;
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = CRYPTO_malloc(num, file, line);

    FAILTEST();
    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}

void *CRYPTO_realloc(void *str, size_t num, const char *file, int line)
{
    INCREMENT(realloc_count);
    if (realloc_impl != NULL && realloc_impl != &CRYPTO_realloc)
        return realloc_impl(str, num, file, line);

    FAILTEST();
    if (str == NULL)
        return CRYPTO_malloc(num, file, line);

    if (num == 0) {
        CRYPTO_free(str, file, line);
        return NULL;
    }

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (call_malloc_debug) {
        void *ret;
        CRYPTO_mem_debug_realloc(str, NULL, num, 0, file, line);
        ret = realloc(str, num);
        CRYPTO_mem_debug_realloc(str, ret, num, 1, file, line);
        return ret;
    }
#else
    (void)(file); (void)(line);
#endif
    return rtos_realloc(str, num);

}

void *CRYPTO_clear_realloc(void *str, size_t old_len, size_t num,
                           const char *file, int line)
{
    void *ret = NULL;

    if (str == NULL)
        return CRYPTO_malloc(num, file, line);

    if (num == 0) {
        CRYPTO_clear_free(str, old_len, file, line);
        return NULL;
    }

    /* Can't shrink the buffer since memcpy below copies |old_len| bytes. */
    if (num < old_len) {
        OPENSSL_cleanse((char*)str + num, old_len - num);
        return str;
    }

    ret = CRYPTO_malloc(num, file, line);
    if (ret != NULL) {
        memcpy(ret, str, old_len);
        CRYPTO_clear_free(str, old_len, file, line);
    }
    return ret;
}

void CRYPTO_free(void *str, const char *file, int line)
{
    INCREMENT(free_count);
    if (free_impl != NULL && free_impl != &CRYPTO_free) {
        free_impl(str, file, line);
        return;
    }

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (call_malloc_debug) {
        CRYPTO_mem_debug_free(str, 0, file, line);
        free(str);
        CRYPTO_mem_debug_free(str, 1, file, line);
    } else {
        free(str);
    }
#else
    rtos_free(str);
#endif
}

void CRYPTO_clear_free(void *str, size_t num, const char *file, int line)
{
    if (str == NULL)
        return;
    if (num)
        OPENSSL_cleanse(str, num);
    CRYPTO_free(str, file, line);
}


struct memory_pool rtos_pool;

#define MEMORY_BLOCK_OVERHEAD sizeof(struct memory_block)

int init_rtos_mempool()
{
    struct memory_block * first;
    first = (struct memory_block*)rtos_pool.buffer;
    first->prev = NULL;
    first->next = NULL;
    first->free = 1;
    first->size = OPENSSL_RTOS_POOL_SIZE - MEMORY_BLOCK_OVERHEAD;
    rtos_pool.free_size = first->size;
    return (first->size == 0);
}

void * rtos_malloc(size_t size)
{
    void * result;
    struct memory_block * block;
    struct memory_block * new_block;
    size_t remaining_size;
    block = (struct memory_block*)rtos_pool.buffer;
    
    result = NULL;
    
    while(block != NULL && result == NULL)
    {
        if(block->free && block->size >= size)
        {
            block->free = 0;
            
            remaining_size = block->size - size;
            
            if(remaining_size > MEMORY_BLOCK_OVERHEAD)
            {
                block->size = size;

                new_block = (struct memory_block*)
                    ((uint8_t*)block + size + MEMORY_BLOCK_OVERHEAD);

                new_block->size = remaining_size 
                                - MEMORY_BLOCK_OVERHEAD;
                
                new_block->free = 1;

                new_block->prev = block;

                new_block->next = block->next;

                if(new_block->next)
                {
                    new_block->next->prev = new_block;
                }

                block->next = new_block;

                rtos_pool.free_size -= MEMORY_BLOCK_OVERHEAD;
            }
            
            rtos_pool.free_size -= block->size;

            result = (uint8_t*)block + MEMORY_BLOCK_OVERHEAD;
        }
        block = block->next;
    }   
    return result;
}

void * rtos_zalloc(size_t size)
{
    void * result;
    result = rtos_malloc(size);
    if(result != NULL)
    {
        (void) memset(result,0,size);
    }
    return result;
}

void rtos_free(void * addr)
{
    struct memory_block *current_header, *prev_header, *next_header;
    uint8_t merge_prev, merge_next;
    uint32_t size_freed;


    current_header = (struct memory_block*)((uint8_t*)addr - MEMORY_BLOCK_OVERHEAD);

    if(current_header->free == 0)
    {
        prev_header = current_header->prev;
        next_header = current_header->next;
        
        // Check if prev is a free block
        merge_prev = (prev_header != NULL) && (prev_header->free == 1);
        
        // Check if next is a free block
        merge_next = (next_header != NULL) && (next_header->free == 1);
        
        // 
        if(merge_prev == 1 && merge_next == 1)
        {
            current_header->free = 1;
            
            size_freed = MEMORY_BLOCK_OVERHEAD 
                       + current_header->size 
                       + MEMORY_BLOCK_OVERHEAD;

            prev_header->size += MEMORY_BLOCK_OVERHEAD 
                              + current_header->size 
                              + MEMORY_BLOCK_OVERHEAD 
                              + next_header->size;
            
            if(next_header->next != NULL)
            {
                next_header->next->prev = prev_header;
            }
            
            prev_header->next = next_header->next;
        }
        else if(merge_prev == 1)
        {
            current_header->free = 1;

            size_freed = MEMORY_BLOCK_OVERHEAD 
                       + current_header->size;

            prev_header->size += MEMORY_BLOCK_OVERHEAD 
                              + current_header->size;

            if(next_header->next != NULL)
            {
                next_header->next->prev = prev_header;
            }
            
            prev_header->next = current_header->next;
        }
        else if(merge_next == 1)
        {
            current_header->free = 1;

            size_freed = current_header->size + MEMORY_BLOCK_OVERHEAD;
            
            current_header->size += MEMORY_BLOCK_OVERHEAD 
                                 + next_header->size;

            if(next_header->next != NULL)
            {
                next_header->next->prev = current_header;
            }

            current_header->next = next_header->next;
        }
        else
        {
            current_header->free = 1;
            size_freed = current_header->size; 
        }

        rtos_pool.free_size += size_freed;
    }
}

static void * resize_block(
    struct memory_block * block, 
    size_t size);

static void * expand_block(
    struct memory_block * block, 
    size_t size);

static void * shrink_block(
    struct memory_block * block, 
    size_t size);

static void * move_block( 
    struct memory_block * block, 
    size_t size);

void * rtos_realloc(void * addr, size_t size)
{
    uint8_t error;
    struct memory_block *block;
    void * result;

    error = (size == 0);

    if(error == 0)
    {
        block = (addr == NULL)?NULL:(struct memory_block*)(
            (uint8_t*)addr - MEMORY_BLOCK_OVERHEAD);
        if(block != NULL)
        {
            result = resize_block(block,size);
        }
        else
        {
            result = rtos_malloc(size);
        }
        
    }
    else
    {
        result = addr;
    }
    
    return result;
}

static void * resize_block(
    struct memory_block * block, 
    size_t size)
{
    void * result;

    if(block->size > size)
    {
        result = shrink_block(block,size);
    }
    else if(block->size < size)
    {
        if((block->next != NULL) 
            && (block->next->free == 1) 
            && (block->size 
                + MEMORY_BLOCK_OVERHEAD 
                + block->next->size) >= size)
        {
            result = expand_block(block,size);
        }
        else
        {
            result = move_block(block,size);
        }
    }
    else
    {
        result = (uint8_t*)block + MEMORY_BLOCK_OVERHEAD;
    }
    
    return result;
}

static void * expand_block(
    struct memory_block * block, 
    size_t size)
{
    void *ptr;
    void *result;
    size_t remaining_size;
    struct memory_block * next_block;

    ptr = (uint8_t*)block + MEMORY_BLOCK_OVERHEAD;

    rtos_pool.free_size += block->size;

    result = ptr;
    remaining_size = (block->size 
        + MEMORY_BLOCK_OVERHEAD 
        + block->next->size) - size;
    if(remaining_size > MEMORY_BLOCK_OVERHEAD)
    {
        next_block = (struct memory_block*)((uint8_t*)result + size);
        next_block->size = remaining_size - MEMORY_BLOCK_OVERHEAD;
        next_block->prev = block;
        next_block->free = 1;
        if(block->next != NULL)
        {
            block->next->prev = next_block;
        }
        next_block->next = block->next;
        block->next = next_block;
        block->size = size;
        rtos_pool.free_size -= block->size;
    }
    
    return result;
}

static void * move_block(
    struct memory_block * block, 
    size_t size)
{
    void * result;
    void * ptr;
    
    result = rtos_malloc(size);
    
    if(result != NULL)
    {
        ptr = (uint8_t*)block + MEMORY_BLOCK_OVERHEAD;
        (void) memcpy(result,ptr,block->size);
        rtos_free(ptr);
    }

    return result;
}

static void * shrink_block(
    struct memory_block * block, 
    size_t size)
{
    void *result;
    struct memory_block * next_block;
    size_t remaining_size;

    result = (uint8_t*)block + MEMORY_BLOCK_OVERHEAD;

    if(block->next != NULL && block->next->free == 1)
    {
        remaining_size = block->size 
                       + MEMORY_BLOCK_OVERHEAD 
                       + block->next->size 
                       - size;
    }
    else
    {
        remaining_size = block->size - size;
    }

    if(remaining_size > MEMORY_BLOCK_OVERHEAD)
    {
        rtos_pool.free_size += block->size - size;
        next_block = (struct memory_block*)((uint8_t*)result + size);
        next_block->size = remaining_size - MEMORY_BLOCK_OVERHEAD;
        next_block->prev = block;
        next_block->free = 1;
        if(block->next != NULL)
        {
            block->next->prev = next_block;
        }
        next_block->next = block->next;
        block->next = next_block;
        block->size = size;
    }

    return result;
}