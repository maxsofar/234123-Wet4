//
// Created by Max on 12/08/2024.
//

#include <unistd.h>
#include <cstring>


struct MallocMetadata {
    size_t size;
    bool is_free;
    MallocMetadata* next;
    MallocMetadata* prev;

    size_t get_size() const {
        return size;
    }

    bool get_is_free() const {
        return is_free;
    }

    MallocMetadata* get_next() const {
        return next;
    }

    void set_is_free(bool is_free) {
        this->is_free = is_free;
    }


};

// Global pointer to the first metadata block
MallocMetadata* head = nullptr;

/*
 * MallocMetadata* findFreeBlock(size_t size):
 * Searches for a free block with at least ‘size’ bytes.
 * Return value:
 *   i.  Success – returns a pointer to the first free block with at least ‘size’ bytes.
 *   ii. Failure – returns nullptr.
 *
 */
MallocMetadata* findFreeBlock(size_t size) {
    MallocMetadata* curr = head;
    while (curr != nullptr) {
        if (curr->get_is_free() && curr->get_size() >= size) {
            return curr;
        }
        curr = curr->get_next();
    }
    return nullptr;
}

/*
 * void* smalloc(size_t size):
 * Searches for a free block with at least ‘size’ bytes or allocates (sbrk()) one if none are found.
 * Return value:
 *   i.  Success – returns pointer to the first byte in the allocated block (excluding the meta-data of course)
 *   ii. Failure –
 *       a. If size is 0 returns NULL.
 *       b. If ‘size’ is more than 10^8, return NULL.
 *       c. If sbrk fails in allocating the needed space, return NULL.
 */

void* smalloc(size_t size)
{
    if (size == 0 || size > 100000000) {
        return nullptr;
    }

    MallocMetadata* free_block = findFreeBlock(size);
    if (free_block == nullptr) {
        void* ptr = sbrk(size + sizeof(MallocMetadata));
        if (ptr == (void*) (-1)) {
            return nullptr;
        }

        // Initialize the MallocMetadata object manually
        auto* new_block = (MallocMetadata*) ptr;
        new_block->size = size;
        new_block->is_free = false;
        new_block->next = nullptr;
        new_block->prev = nullptr;

        if (head == nullptr) {
            head = new_block;
        } else {
            MallocMetadata* curr = head;
            while (curr->next != nullptr) {
                curr = curr->next;
            }
            curr->next = new_block;
            new_block->prev = curr;
        }

        return (void*) ((char*) ptr + sizeof(MallocMetadata));
    }

    free_block->set_is_free(false);
    return (void*) ((char*) free_block + sizeof(MallocMetadata));
}

/*
 * void* scalloc(size_t num, size_t size):
 * Searches for a free block of at least ‘num’ elements, each ‘size’ bytes that are all set to 0 or allocates if none are found. In other words, find/allocate size * num bytes and set all bytes to 0.
 * Return value:
 * i.  Success - returns pointer to the first byte in the allocated block.
 * ii. Failure –
 *     a. If size or num is 0 returns NULL.
 *     b. If ‘size * num’ is more than 10^8, return NULL.
 *     c. If sbrk fails in allocating the needed space, return NULL.
 */

void* scalloc(size_t num, size_t size)
{
    if (num == 0 || size == 0 || num * size > 100000000) {
        return nullptr;
    }

    void* ptr = smalloc(num * size);
    if (ptr == nullptr) {
        return nullptr;
    }

    // Initialize the allocated block to 0
    memset(ptr, 0, num * size);
    return ptr;
}

/*
 * void sfree(void* p):
 * Releases the usage of the block that starts with the pointer ‘p’.
 * If ‘p’ is NULL or already released, simply returns.
 * Presume that all pointers ‘p’ truly points to the beginning of an allocated block.
 */

void sfree(void* p)
{
    if (p == nullptr) {
        return;
    }

    MallocMetadata* curr = head;
    while (curr != nullptr) {
        if ((void*) ((char*) curr + sizeof(MallocMetadata)) == p) {
            curr->set_is_free(true);
            return;
        }
        curr = curr->get_next();
    }
}

/*
 * void* srealloc(void* oldp, size_t size):
 * If ‘size’ is smaller than or equal to the current block’s size, reuses the same block.
 * Otherwise, finds/allocates ‘size’ bytes for a new space, copies content of oldp into the new allocated space and frees the oldp.
 * Return value:
 * i. Success –
 *      a. Returns pointer to the first byte in the (newly) allocated space.
 *      b. If ‘oldp’ is NULL, allocates space for ‘size’ bytes and returns a pointer to it.
 * ii.Failure –
 *      a. If size is 0 returns NULL.
 *      b. If ‘size’ if more than 10^8, return NULL.
 *      c. If sbrk fails in allocating the needed space, return NULL.
 *      d. Do not free ‘oldp’ if srealloc() fails.
 */

void* srealloc(void* oldp, size_t size)
{
    if (size == 0 || size > 100000000) {
        return nullptr;
    }

    //TODO: check the same in malloc_3.cpp
    if (oldp == nullptr) {
        return smalloc(size);
    }

    MallocMetadata* curr = head;
    while (curr != nullptr) {
        if ((void*) ((char*) curr + sizeof(MallocMetadata)) == oldp) {
            if (curr->get_size() >= size) {
                return oldp;
            }

            void* new_ptr = smalloc(size);
            if (new_ptr == nullptr) {
                return nullptr;
            }

            memmove(new_ptr, oldp, curr->get_size());
            sfree(oldp);
            return new_ptr;
        }
        curr = curr->get_next();
    }
    return nullptr;
}


/*
 * size_t _num_free_blocks():
 * Returns the number of allocated blocks in the heap that are currently free.
 */
size_t _num_free_blocks() {
    size_t count = 0;
    MallocMetadata* curr = head;
    while (curr != nullptr) {
        if (curr->get_is_free()) {
            count++;
        }
        curr = curr->get_next();
    }
    return count;
}

/*
 * size_t _num_free_bytes():
 * Returns the number of bytes in all allocated blocks in the heap that are currently free,
 * excluding the bytes used by the meta-data structs.
 */
size_t _num_free_bytes() {
    size_t total_free_bytes = 0;
    MallocMetadata* curr = head;
    while (curr != nullptr) {
        if (curr->get_is_free()) {
            total_free_bytes += curr->get_size();
        }
        curr = curr->get_next();
    }
    return total_free_bytes;
}

/*
 * size_t _num_allocated_blocks():
 * Returns the overall (free and used) number of allocated blocks in the heap.
 */
size_t _num_allocated_blocks() {
    size_t count = 0;
    MallocMetadata* curr = head;
    while (curr != nullptr) {
        count++;
        curr = curr->get_next();
    }
    return count;
}

/*
 * size_t _num_allocated_bytes():
 * Returns the overall number (free and used) of allocated bytes in the heap, excluding
 * the bytes used by the meta-data structs.
 */
size_t _num_allocated_bytes() {
    size_t total_allocated_bytes = 0;
    MallocMetadata* curr = head;
    while (curr != nullptr) {
        total_allocated_bytes += curr->get_size();
        curr = curr->get_next();
    }
    return total_allocated_bytes;
}

/*
 * size_t _num_meta_data_bytes():
 * Returns the overall number of meta-data bytes currently in the heap.
 */
size_t _num_meta_data_bytes() {
    size_t total_meta_data_bytes = 0;
    MallocMetadata* curr = head;
    while (curr != nullptr) {
        total_meta_data_bytes += sizeof(MallocMetadata);
        curr = curr->get_next();
    }
    return total_meta_data_bytes;
}

/*
 * size_t _size_meta_data():
 * Returns the number of bytes of a single meta-data structure in your system.
 */
size_t _size_meta_data() {
    return sizeof(MallocMetadata);
}