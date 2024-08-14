//
// Created by Max on 12/08/2024.
//

#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <sys/mman.h>


#define MAX_ORDER 10
#define MIN_BLOCK_SIZE 128 // 128 bytes
#define INITIAL_BLOCKS 32
#define MAX_BLOCK_SIZE (MIN_BLOCK_SIZE << MAX_ORDER) // 128 KB


// size(MallocMetadata) = 32 bytes
struct MallocMetadata {
    size_t size;
    bool is_free;
    bool is_mmap = false;
    MallocMetadata* next;
    MallocMetadata* prev;

    size_t get_size() const { return size; }
    void set_size(size_t size) { this->size = size; }
    bool get_is_free() const { return is_free; }
    void set_is_free(bool is_free) { this->is_free = is_free; }
    bool get_is_mmap() const { return is_mmap; }
    void set_is_mmap(bool is_mmap) { this->is_mmap = is_mmap; }
    MallocMetadata* get_next() const { return next; }
    void set_next(MallocMetadata* next) { this->next = next; }
    void set_prev(MallocMetadata* prev) { this->prev = prev; }
    MallocMetadata* get_prev() const { return prev; }

};
struct Stats {
    size_t num_free_blocks = 0;
    size_t num_used_blocks = 0;
    size_t num_free_bytes = 0;
};

MallocMetadata* free_lists[MAX_ORDER + 1] = {nullptr};
MallocMetadata* mmap_head = nullptr;
bool is_memory_pool_initialized = false;
Stats stats;

void initialize_memory_pool() {
    // Align memory
    void* aligned_memory = sbrk(0);
    if ((uintptr_t)aligned_memory % (INITIAL_BLOCKS * MAX_BLOCK_SIZE) != 0) {
        sbrk((INITIAL_BLOCKS * MAX_BLOCK_SIZE) - ((uintptr_t)aligned_memory % (INITIAL_BLOCKS * MAX_BLOCK_SIZE)));
    }

    // Allocate initial blocks
    void* initial_memory = sbrk(INITIAL_BLOCKS * MAX_BLOCK_SIZE);
    if (initial_memory == (void*)-1) {
        return;
    }

    // Initialize free list with 32 blocks of 128 KB
    for (int i = 0; i < INITIAL_BLOCKS; ++i) {
        auto* block = (MallocMetadata*)((char*)initial_memory + i * MAX_BLOCK_SIZE);
        block->set_size(MAX_BLOCK_SIZE);
        block->set_is_free(true);
        block->set_next(free_lists[MAX_ORDER]);
        if (free_lists[MAX_ORDER] != nullptr) {
            free_lists[MAX_ORDER]->set_prev(block);
        }
        free_lists[MAX_ORDER] = block;
    }

    // Update stats
    stats.num_free_blocks = INITIAL_BLOCKS;
    stats.num_free_bytes = INITIAL_BLOCKS * MAX_BLOCK_SIZE;
    stats.num_used_blocks = 0; // Initialize used blocks to 0

    is_memory_pool_initialized = true;
}

int getOrder(size_t size) {
    int order = 0;
    size_t blockSize = MIN_BLOCK_SIZE;

    while (order <= MAX_ORDER && blockSize < size) {
        order++;
        blockSize <<= 1; // Double the block size
    }

    return (order > MAX_ORDER) ? -1 : order;
}

// Helper function to remove the first block from the free list of a given order
MallocMetadata* removeBlockFromFreeList(int order) {
    MallocMetadata* block = free_lists[order];
    if (block != nullptr) {
        free_lists[order] = block->get_next();
        if (block->get_next() != nullptr) {
            block->get_next()->set_prev(nullptr);
        }
        block->set_is_free(false);
    }
    return block;
}

// Helper function to split a block into smaller blocks
void splitBlock(MallocMetadata* block, int current_order, int target_order) {
    while (current_order > target_order) {
        current_order--;
        size_t split_size = MIN_BLOCK_SIZE << current_order;
        auto* split_block = (MallocMetadata*)((char*)block + split_size);
        split_block->set_size(split_size);
        split_block->set_is_free(true);

        // Add the split block to the free list
        split_block->set_next(free_lists[current_order]);
        if (free_lists[current_order] != nullptr) {
            free_lists[current_order]->set_prev(split_block);
        }
        free_lists[current_order] = split_block;

        // Update stats for each split
        stats.num_free_blocks++;
    }
    block->set_size(MIN_BLOCK_SIZE << target_order);
}

MallocMetadata* findFreeBlock(size_t size) {
    int order = getOrder(size);
    if (order == -1) {
        return nullptr;
    }

    for (int current_order = order; current_order <= MAX_ORDER; ++current_order) {
        MallocMetadata* block = removeBlockFromFreeList(current_order);
        if (block != nullptr) {
            splitBlock(block, current_order, order);
            return block;
        }
    }
    return nullptr;
}

void* smalloc(size_t size) {
    if (size == 0 || size > 100000000) {
        return nullptr;
    }

    if (size >= 128 * 1024) {
        // Use mmap for large allocations
        void* ptr = mmap(nullptr, size + sizeof(MallocMetadata), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) {
            return nullptr;
        }
        auto* metadata = (MallocMetadata*)ptr;
        metadata->set_size(size);
        metadata->set_is_free(false);
        metadata->set_is_mmap(true);
        metadata->set_next(mmap_head);
        mmap_head = metadata;

        // Update stats
        stats.num_used_blocks++;

        return (void*)((char*)ptr + sizeof(MallocMetadata));
    }

    if (!is_memory_pool_initialized) {
        initialize_memory_pool();
    }

    MallocMetadata* block = findFreeBlock(size);
    if (block == nullptr) {
        return nullptr;
    }

    // Update stats
    stats.num_free_blocks--;
    int blockSize = block->get_size();
    stats.num_free_bytes -= blockSize;
    stats.num_used_blocks++;

    return (void*)((char*)block + sizeof(MallocMetadata));
}


void* scalloc(size_t num, size_t size) {
    if (num == 0 || size == 0 || num * size > 100000000) {
        return nullptr;
    }

    size_t total_size = num * size;
    void* ptr = smalloc(total_size);
    if (ptr != nullptr) {
        memset(ptr, 0, total_size);
    }

    // Update stats
    stats.num_used_blocks++;

    return ptr;
}


//--------------------------------- sfree ---------------------------------

// Function to find the buddy block address
void* findBuddy(void* block, size_t size) {
    return (void*)((uintptr_t)block ^ size);
}

// Helper function to add a block to the free list in ascending order of addresses
void addBlockToFreeList(MallocMetadata* block, int order) {
    MallocMetadata* current = free_lists[order];
    MallocMetadata* prev = nullptr;

    // Find the correct position to insert the block
    while (current != nullptr && current < block) {
        prev = current;
        current = current->get_next();
    }

    // Insert the block into the list
    block->set_next(current);
    block->set_prev(prev);
    if (current != nullptr) {
        current->set_prev(block);
    }
    if (prev != nullptr) {
        prev->set_next(block);
    } else {
        free_lists[order] = block;
    }
    block->set_is_free(true);
}

// Helper function to merge buddy blocks and return the merged block
MallocMetadata* tryMergeBuddyBlocks(MallocMetadata* block, size_t size, int& order, size_t& total_size) {
    while (order < MAX_ORDER) {
        void* buddy_address = findBuddy((void*)block, MIN_BLOCK_SIZE << order);
        auto* buddy = (MallocMetadata*)buddy_address;

        if (buddy->get_is_free() && buddy->get_size() == static_cast<size_t>(MIN_BLOCK_SIZE << order)) {
            // Remove buddy from free list
            if (buddy->get_prev() != nullptr) {
                buddy->get_prev()->set_next(buddy->get_next());
            } else {
                free_lists[order] = buddy->get_next();
            }
            if (buddy->get_next() != nullptr) {
                buddy->get_next()->set_prev(buddy->get_prev());
            }

            total_size += buddy->get_size();
            if (buddy < block) {
                block = buddy;
            }
            order++;
            // Update stats for each merge
            stats.num_free_blocks--;
        } else {
            break;
        }
    }
    return block;
}

void mergeBuddyBlocks(MallocMetadata* block, int order) {
    size_t total_size = block->get_size();
    MallocMetadata* merged_block = tryMergeBuddyBlocks(block, total_size, order, total_size);
    addBlockToFreeList(merged_block, order);
}

void sfree(void* p) {
    if (p == nullptr) {
        return;
    }

    auto* block = (MallocMetadata*)((char*)p - sizeof(MallocMetadata));
    if (block->get_is_free()) {
        return; // Block is already free, do nothing
    }
    if (block->get_is_mmap()) {
        // Remove from mmap list
        if (mmap_head == block) {
            mmap_head = block->get_next();
        } else {
            MallocMetadata* curr = mmap_head;
            while (curr != nullptr && curr->get_next() != block) {
                curr = curr->get_next();
            }
            if (curr != nullptr) {
                curr->set_next(block->get_next());
            }
        }
        munmap(block, block->get_size() + sizeof(MallocMetadata));

        // Update stats
        stats.num_used_blocks--;

        return;
    }

    block->set_is_free(true);
    // Update stats
    stats.num_free_blocks++;
    stats.num_free_bytes += block->get_size();
    stats.num_used_blocks--;

    int order = getOrder(block->get_size());
    mergeBuddyBlocks(block, order);


}

//--------------------------------- srealloc ---------------------------------


// Handle mmaped blocks
void* handle_mmaped_block(MallocMetadata* curr, void* oldp, size_t size) {
    if (curr->get_size() == size) {
        return oldp;
    }

    void* new_ptr = mmap(nullptr, size + sizeof(MallocMetadata), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_ptr == MAP_FAILED) {
        return nullptr;
    }

    auto* new_metadata = (MallocMetadata*)new_ptr;
    new_metadata->set_size(size);
    new_metadata->set_is_free(false);
    new_metadata->set_is_mmap(true);
    new_metadata->set_next(mmap_head);
    mmap_head = new_metadata;

    memmove((char*)new_ptr + sizeof(MallocMetadata), oldp, curr->get_size());
    munmap(curr, curr->get_size() + sizeof(MallocMetadata));
    return (char*)new_ptr + sizeof(MallocMetadata);
}

void* srealloc(void* oldp, size_t size) {
    if (size == 0 || size > 100000000) {
        return nullptr;
    }

    if (oldp == nullptr) {
        return smalloc(size);
    }

    auto* curr = (MallocMetadata*)((char*)oldp - sizeof(MallocMetadata));

    // Handle mmaped blocks
    if (curr->get_is_mmap()) {
        return handle_mmaped_block(curr, oldp, size);
    }

    // Reuse the current block if possible
    if (curr->get_size() >= size) {
        return oldp;
    }

    // Check if merging with buddy blocks can provide a large enough block
    size_t total_size = curr->get_size();
    MallocMetadata* block = curr;
    int order = getOrder(curr->get_size());

    while (order < MAX_ORDER) {
        void* buddy_address = findBuddy((void*)block, MIN_BLOCK_SIZE << order);
        auto* buddy = (MallocMetadata*)buddy_address;

        if (buddy->get_is_free() && buddy->get_size() == static_cast<size_t>(MIN_BLOCK_SIZE << order)) {
            total_size += buddy->get_size();
            if (buddy < block) {
                block = buddy;
            }
            order++;
            if (total_size >= size) {
                mergeBuddyBlocks(block, order);
                return (char*)block + sizeof(MallocMetadata);
            }
        } else {
            break;
        }
    }

    // Find a different block that is large enough
    void* new_ptr = smalloc(size);
    if (new_ptr == nullptr) {
        return nullptr;
    }

    memmove(new_ptr, oldp, curr->get_size());
    sfree(oldp);

    // Update stats
    stats.num_used_blocks++;

    return new_ptr;
}


//--------------------------------- stats ---------------------------------
size_t _num_free_blocks() {
    return stats.num_free_blocks;
}

size_t _num_free_bytes() {
    return stats.num_free_bytes - (stats.num_free_blocks * sizeof(MallocMetadata));
}

size_t _num_allocated_blocks() {
    return stats.num_free_blocks + stats.num_used_blocks;
}

size_t _num_meta_data_bytes() {
    return (stats.num_free_blocks + stats.num_used_blocks) * sizeof(MallocMetadata);
}

size_t _num_allocated_bytes() {
    if (!is_memory_pool_initialized) {
        return 0;
    }

    size_t allocated_bytes = INITIAL_BLOCKS * MAX_BLOCK_SIZE - _num_meta_data_bytes();

    // Add the size of mmaped blocks and subtract their metadata size
    MallocMetadata* current = mmap_head;
    while (current != nullptr) {
        allocated_bytes += current->get_size();
        //TODO: strange....metadata included???
        allocated_bytes += sizeof(MallocMetadata); // ADD metadata size
        current = current->get_next();
    }
    return allocated_bytes;
}

size_t _size_meta_data() {
    return sizeof(MallocMetadata);
}