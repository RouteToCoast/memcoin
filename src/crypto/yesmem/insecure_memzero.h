#ifndef INSECURE_MEMZERO_H
#define INSECURE_MEMZERO_H

#include <stddef.h>

static inline void insecure_memzero(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--)
        *p++ = 0;
}

#endif /* INSECURE_MEMZERO_H */
