//
// Created by Max on 11/08/2024.
//

/*
    void* smalloc(size_t size)
    ● Tries to allocate ‘size’ bytes.
    ● Return value:
    i. Success –a pointer to the first allocated byte within the allocated block.
    ii. Failure –
    a. If ‘size’ is 0 returns NULL.
    b. If ‘size’ is more than 10^8 return NULL.
    c. If sbrk fails, return NULL.
 */

#include <unistd.h>

void* smalloc(size_t size)
{
    if (size == 0 || size > 100000000) {
        return NULL;
    }

    void* ptr = sbrk(size);
    if (ptr == (void*) (-1)) {
        return NULL;
    }

    return ptr;
}