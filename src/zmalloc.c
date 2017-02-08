/* zmalloc - total amount of allocated memory aware version of malloc()
 *
 * Copyright (c) 2009-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>

/* This function provide us access to the original libc free(). This is useful
 * for instance to free results obtained by backtrace_symbols(). We need
 * to define this function before including zmalloc.h that may shadow the
 * free implementation if we use jemalloc or another non standard allocator. */
// 原始系统free释放方法
void zlibc_free(void *ptr) {
    free(ptr);
}

#include <string.h>
#include <pthread.h>
#include "config.h"
#include "zmalloc.h"

#ifdef HAVE_MALLOC_SIZE
#define PREFIX_SIZE (0)
#else
#if defined(__sun) || defined(__sparc) || defined(__sparc__)
#define PREFIX_SIZE (sizeof(long long))
#else
#define PREFIX_SIZE (sizeof(size_t))
#endif
#endif

/* Explicitly override malloc/free etc when using tcmalloc. */
// 宏定义malloc,calloc,realloc,free等内存操作相关函数(默认使用linux系统的相关函数)
#if defined(USE_TCMALLOC)
#define malloc(size) tc_malloc(size)
#define calloc(count,size) tc_calloc(count,size)
#define realloc(ptr,size) tc_realloc(ptr,size)
#define free(ptr) tc_free(ptr)
#elif defined(USE_JEMALLOC)
#define malloc(size) je_malloc(size)
#define calloc(count,size) je_calloc(count,size)
#define realloc(ptr,size) je_realloc(ptr,size)
#define free(ptr) je_free(ptr)
#endif

// 更新used_memory变量相关的函数
#ifdef HAVE_ATOMIC
// 如果定义了原子操作标志，则使用操作系统相关的原子操作API来增加used_memory变量
#define update_zmalloc_stat_add(__n) __sync_add_and_fetch(&used_memory, (__n))
// 如果定义了原子操作标志，则使用操作系统相关的原子操作API来减少used_memory变量
#define update_zmalloc_stat_sub(__n) __sync_sub_and_fetch(&used_memory, (__n))
#else
// 如果没有定义原子操作标志，则通过加锁来增加used_memory变量
#define update_zmalloc_stat_add(__n) do { \
    pthread_mutex_lock(&used_memory_mutex); \
    used_memory += (__n); \
    pthread_mutex_unlock(&used_memory_mutex); \
} while(0)

// 如果没有定义原子操作标志，则通过加锁来减少used_memory变量
#define update_zmalloc_stat_sub(__n) do { \
    pthread_mutex_lock(&used_memory_mutex); \
    used_memory -= (__n); \
    pthread_mutex_unlock(&used_memory_mutex); \
} while(0)

#endif

// 申请内存成功，然后统计内存使用量
#define update_zmalloc_stat_alloc(__n) do { \
    size_t _n = (__n); \
    if (_n & (sizeof(long) - 1)) _n += sizeof(long) - (_n & (sizeof(long) - 1)); \
    if (zmalloc_thread_safe) { \
        update_zmalloc_stat_add(_n); \
    } else { \
        used_memory += _n; \
    } \
} while(0)

// 释放内存成功，然后统计内存使用量
#define update_zmalloc_stat_free(__n) do { \
    size_t _n = (__n); \
    if (_n & (sizeof(long) - 1)) _n += sizeof(long) - (_n & (sizeof(long) - 1)); \
    if (zmalloc_thread_safe) { \
        update_zmalloc_stat_sub(_n); \
    } else { \
        used_memory -= _n; \
    } \
} while(0)

// redis服务器已经使用的内存大小,用一个全局变量来存储(已经申请的内存总字节数)
static size_t used_memory = 0;
// 标识是否是线程安全的，默认为0，不安全
static int zmalloc_thread_safe = 0;
// 将used_memory作为临界变量，锁住此变量
pthread_mutex_t used_memory_mutex = PTHREAD_MUTEX_INITIALIZER;

// 默认的内存申请相关错误的默认处理函数
static void zmalloc_default_oom(size_t size) {
    fprintf(stderr, "zmalloc: Out of memory trying to allocate %zu bytes\n",
        size);
    fflush(stderr);
    abort();
}

static void (*zmalloc_oom_handler)(size_t) = zmalloc_default_oom;

// 申请size大小的内存(如果没有定义HAVE_MALLOC_SIZE，则需要额外PREFIX_SIZE大小的内存来存储该内存空间的大小，如果
// 有定义的话，则不需要额外的空间来存储内存空间大小)
void *zmalloc(size_t size) {
    void *ptr = malloc(size + PREFIX_SIZE);

    // 如果没有申请成功，则调用zmalloc_oom_handler句柄处理内存不足的情况
    if (!ptr) zmalloc_oom_handler(size);
    // 如果有统计单个地址对应申请的内存大小，则只需要去将申请的内存大小添加到used_memory变量上
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
    // 如果没有统计单个地址对应申请的内存大小，则需要把自己统计申请内存大小的size统计到used_memory变量上，
    // 然后将申请的地址去掉统计申请内存大小的PREFIX_SIZE长度返回给调用次函数的对象
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size + PREFIX_SIZE);
    return (char*)ptr + PREFIX_SIZE;
#endif
}

// calloc申请内存空间函数接口
void *zcalloc(size_t size) {
    // 实际申请空间的动作
    void *ptr = calloc(1, size + PREFIX_SIZE);

    // 如果没有申请成功，则调用zmalloc_oom_handler句柄处理内存不足的情况
    if (!ptr) zmalloc_oom_handler(size);
    // 如果定义了HAVE_MALLOC_SIZE，则不需要用额外的内存空间来存储申请内存空间的大小,
    // 直接统计总的申请的内存空间大小
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
    // 如果没有定义HAVE_MALLOC_SIZE，则需要用额外的空间存储申请到的地址空间的大小，然后去
    // 更新used_memory全局变量的大小
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size + PREFIX_SIZE);
    return (char*)ptr + PREFIX_SIZE;
#endif
}

// zrealloc函数接口，给一个已经分配了地址的指针重新分配空间,参数ptr为原有的空间地址,size是重新申请的地址长度
void *zrealloc(void *ptr, size_t size) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
#endif
    size_t oldsize;
    void *newptr;

    // 如果ptr为空，则直接申请size大小的空间，然后返回
    if (ptr == NULL) return zmalloc(size);
#ifdef HAVE_MALLOC_SIZE
    // 得到老的ptr地址对应的内存空间大小
    oldsize = zmalloc_size(ptr);
    // 调用realloc重新申请内存
    newptr = realloc(ptr, size);
    // 如果申请内存失败，则调用处理句柄函数进行处理
    if (!newptr) zmalloc_oom_handler(size);

    // 将老的内存空间从总的内存空间used_memory中减去
    update_zmalloc_stat_free(oldsize);
    // 将新申请的内存空间大小增加到used_memory变量中
    update_zmalloc_stat_alloc(zmalloc_size(newptr));
    return newptr;
#else
    // 先得到老的ptr实际的内存起始地址
    realptr = (char*)ptr - PREFIX_SIZE;
    // 得到老的ptr对应的内存空间的大小
    oldsize = *((size_t*)realptr);
    // 调用realloc函数进行内存空间的申请
    newptr = realloc(realptr, size + PREFIX_SIZE);
    // 如果申请内存失败，则调用处理句柄函数进行处理
    if (!newptr) zmalloc_oom_handler(size);

    // 存储新申请的内存大小到PREFIX_SIZE
    *((size_t*)newptr) = size;
    // 将老的内存空间从总的内存空间used_memory中减去
    update_zmalloc_stat_free(oldsize);
    // 将新申请的内存空间大小增加到used_memory变量中
    update_zmalloc_stat_alloc(size);
    // 将实际的内存起始地址返回给调用者
    return (char*)newptr + PREFIX_SIZE;
#endif
}

/* Provide zmalloc_size() for systems where this function is not provided by
 * malloc itself, given that in that case we store a header with this
 * information as the first bytes of every allocation. */
// redis自定义的统计一个内存地址使用的内存大小(jemalloc,tcmalloc,苹果操作系统这三种内存分配器定义有自己的统计内存大小函数)
#ifndef HAVE_MALLOC_SIZE
size_t zmalloc_size(void *ptr) {
    void *realptr = (char*)ptr - PREFIX_SIZE;
    size_t size = *((size_t*)realptr);
    /* Assume at least that all the allocations are padded at sizeof(long) by
     * the underlying allocator. */
    if (size & (sizeof(long) - 1)) size += sizeof(long) - (size & (sizeof(long) - 1));
    return size + PREFIX_SIZE;
}
#endif

// 释放内存的函数接口
void zfree(void *ptr) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
    size_t oldsize;
#endif

    // 如果ptr为空，则直接返回
    if (ptr == NULL) return;
    // 如果定义了HAVE_MALLOC_SIZE，则直接将内存空间从used_memory中减去，然后释放掉内存
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_free(zmalloc_size(ptr));
    free(ptr);
    // 如果没有定义HAVE_MALLOC_SIZE，则首先得到内存大小，然后将内存大小从used_memory中减去，
    // 然后释放内存
#else
    // 得到真实的内存起始地址
    realptr = (char*)ptr - PREFIX_SIZE;
    // 得到内存地址对应的内存大小
    oldsize = *((size_t*)realptr);
    // 将内存大小从used_memory中减去
    update_zmalloc_stat_free(oldsize + PREFIX_SIZE);
    // 释放内存的实际动作
    free(realptr);
#endif
}

char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;
    char *p = zmalloc(l);

    memcpy(p,s,l);
    return p;
}

// 返回redis系统总的内存申请大小
size_t zmalloc_used_memory(void) {
    size_t um;

    if (zmalloc_thread_safe) {
#ifdef HAVE_ATOMIC
        um = __sync_add_and_fetch(&used_memory, 0);
#else
        pthread_mutex_lock(&used_memory_mutex);
        um = used_memory;
        pthread_mutex_unlock(&used_memory_mutex);
#endif
    }
    else {
        um = used_memory;
    }

    return um;
}

// 开启线程安全
void zmalloc_enable_thread_safeness(void) {
    zmalloc_thread_safe = 1;
}

// 设置内存申请失败之后的处理句柄
void zmalloc_set_oom_handler(void (*oom_handler)(size_t)) {
    zmalloc_oom_handler = oom_handler;
}

/* Get the RSS information in an OS-specific way.
 *
 * WARNING: the function zmalloc_get_rss() is not designed to be fast
 * and may not be called in the busy loops where Redis tries to release
 * memory expiring or swapping out objects.
 *
 * For this kind of "fast RSS reporting" usages use instead the
 * function RedisEstimateRSS() that is a much faster (and less precise)
 * version of the function. */

#if defined(HAVE_PROC_STAT)
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

size_t zmalloc_get_rss(void) {
    int page = sysconf(_SC_PAGESIZE);
    size_t rss;
    char buf[4096];
    char filename[256];
    int fd, count;
    char *p, *x;

    snprintf(filename,256,"/proc/%d/stat",getpid());
    if ((fd = open(filename,O_RDONLY)) == -1) return 0;
    if (read(fd,buf,4096) <= 0) {
        close(fd);
        return 0;
    }
    close(fd);

    p = buf;
    count = 23; /* RSS is the 24th field in /proc/<pid>/stat */
    while(p && count--) {
        p = strchr(p,' ');
        if (p) p++;
    }
    if (!p) return 0;
    x = strchr(p,' ');
    if (!x) return 0;
    *x = '\0';

    rss = strtoll(p,NULL,10);
    rss *= page;
    return rss;
}
#elif defined(HAVE_TASKINFO)
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/task.h>
#include <mach/mach_init.h>

size_t zmalloc_get_rss(void) {
    task_t task = MACH_PORT_NULL;
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (task_for_pid(current_task(), getpid(), &task) != KERN_SUCCESS)
        return 0;
    task_info(task, TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count);

    return t_info.resident_size;
}
#else
size_t zmalloc_get_rss(void) {
    /* If we can't get the RSS in an OS-specific way for this system just
     * return the memory usage we estimated in zmalloc()..
     *
     * Fragmentation will appear to be always 1 (no fragmentation)
     * of course... */
    return zmalloc_used_memory();
}
#endif

/* Fragmentation = RSS / allocated-bytes */
float zmalloc_get_fragmentation_ratio(size_t rss) {
    return (float)rss/zmalloc_used_memory();
}

#if defined(HAVE_PROC_SMAPS)
size_t zmalloc_get_private_dirty(void) {
    char line[1024];
    size_t pd = 0;
    FILE *fp = fopen("/proc/self/smaps","r");

    if (!fp) return 0;
    while(fgets(line,sizeof(line),fp) != NULL) {
        if (strncmp(line,"Private_Dirty:",14) == 0) {
            char *p = strchr(line,'k');
            if (p) {
                *p = '\0';
                pd += strtol(line+14,NULL,10) * 1024;
            }
        }
    }
    fclose(fp);
    return pd;
}
#else
size_t zmalloc_get_private_dirty(void) {
    return 0;
}
#endif
