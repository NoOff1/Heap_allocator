#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define HEAP_SIZE (1024 * 1024)     //1 MB of heap
#define MAX_PTRS 100
#define ALIGNMENT sizeof(void*)
#define ALIGN(size) (((size) + ALIGNMENT - 1) & ~(ALIGNMENT - 1))

typedef struct block
{
    size_t size;            //Size of the data area
    int free;               //1 = free, 0 = used
    struct block* next;     //Pointer to next block
} block_t;

#define BLOCK_SIZE sizeof(block_t)

void* heap_start = NULL;
block_t* free_list = NULL;
void* user_ptrs[MAX_PTRS];

//Initializes the heap
void init_heap ()
{
    if (!heap_start)
    {
        heap_start = sbrk(HEAP_SIZE);
        if (heap_start == (void*)-1)
        {
            perror("Failed to initialize the heap.");
            exit(EXIT_FAILURE);
        }
        free_list = (block_t*)heap_start;
        free_list->size = HEAP_SIZE - BLOCK_SIZE;
        free_list->free = 1;
        free_list->next = NULL;
        memset(user_ptrs, 0, sizeof(user_ptrs));
    }
}

//Splits the allocated block if too big
void split_block (block_t* block, size_t size)
{
    if (block->size >= size + BLOCK_SIZE + ALIGNMENT)
    {
        block_t* new_block = (block_t*)((char*)block + BLOCK_SIZE + size);
        new_block->size = block->size - size - BLOCK_SIZE;
        new_block->free = 1;
        new_block->next = block->next;

        block->size = size;
        block->next = new_block;
    }
}

//Allocates memory
void* my_malloc (size_t size)
{
    if (!size) return NULL;
    size = ALIGN(size);
    if (!heap_start) init_heap();

    block_t* current = free_list;
    while (current)
    {
        if (current->free && current->size >= size)
        {
            split_block(current, size);
            current->free = 0;
            return (char*)current + BLOCK_SIZE;
        }
        current = current->next;
    }
    return NULL;
}

//Frees a pointer by index
void my_free (void* ptr)
{
    if (!ptr) return;

    block_t* block = (block_t*)((char*)ptr - BLOCK_SIZE);
    if (block->free)
    {
        printf("Warning: Double free detected.\n");
        return;
    }

    block->free = 1;

    block_t* current = free_list;
    while (current && current->next)
    {
        if (current->free && current->next->free)
        {
            current->size += BLOCK_SIZE + current->next->size;
            current->next = current->next->next;
        }
        else current = current->next;
    }
}

//Zero-initializes allocation
void* my_calloc (size_t num, size_t size)
{
    if (size && num > SIZE_MAX / size) return NULL;
    size_t total = num * size;
    void* ptr = my_malloc(total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

//Re-allocates previously allocated block
void* my_realloc (void* ptr, size_t size)
{
    if (!ptr) return my_malloc(size);
    block_t* block = (block_t*)((char*)ptr - BLOCK_SIZE);
    if (block->size >= size) return ptr;

    void* new_ptr = my_malloc(size);
    if (!new_ptr) return NULL;
    memcpy(new_ptr, ptr, block->size);
    my_free(ptr);
    return new_ptr;
}

//Prints the state of the heap and user pointers
void print_state ()
{
    printf("\n[HEAP STATE]\n");
    block_t* current = free_list;
    int i = 0;
    while (current)
    {
        printf("Block %d: %zu bytes - %s\n", i++, current->size, current->free ? "FREE" : "USED");
        current = current->next;
    }

    printf("\n[USER POINTERS]\n");
    for (int i = 0; i < MAX_PTRS; i++)
    {
        if (user_ptrs[i])
        {
            printf("Index %d: %p\n", i, user_ptrs[i]);
        }
    }
    printf("\n");
}

//Stores the pointer in array
int store_ptr (void* ptr)
{
    for (int i = 0; i < MAX_PTRS; i++)
    {
        if (!user_ptrs[i])
        {
            user_ptrs[i] = ptr;
            return i;
        }
    }
    return -1;
}

//Frees the pointer index
void free_ptr_index (int index)
{
    if (index >= 0 && index < MAX_PTRS && user_ptrs[index])
    {
        my_free(user_ptrs[index]);
        user_ptrs[index] = NULL;
        printf("Freed memory at index %d.\n", index);
    }
    else printf("Invalid index or already freed.\n");
}

//Reallocates the pointer index
void realloc_ptr_index (int index, size_t new_size)
{
    if (index >= 0 && index < MAX_PTRS && user_ptrs[index])
    {
        void* new_ptr = my_realloc(user_ptrs[index], new_size);
        if (new_ptr) 
        {
            user_ptrs[index] = new_ptr;
            printf("Realloced memory at index %d to %zu bytes.\n", index, new_size);
        }
        else printf("Realloc failed.\n");
    }
    else printf("Invalid index.\n");
}

void sanitize_input (char* input)
{
    input[strcspn(input, "\n")] = 0;
}

int main ()
{
    init_heap();
    char command[64];

    printf("CUSTOM HEAP ALLOCATOR\n\n");
    printf("Commands: malloc SIZE | calloc N SIZE | realloc INDEX SIZE | free INDEX | print | exit\n\n");

    while (1)
    {
        printf(">>> ");
        if (!fgets(command, sizeof(command), stdin)) break;
        sanitize_input(command);

        if (strncmp(command, "malloc", 6) == 0)
        {
            size_t size;
            if (sscanf(command + 7, "%zu", &size) != 1)
            {
                printf("Usage: malloc SIZE\n");
                continue;
            }

            void* ptr = my_malloc(size);
            int index = store_ptr(ptr);

            if (index >= 0) printf("Allocated %zu bytes at index %d (%p).\n", size, index, ptr);
            else printf("Allocation failed or the pointer array is full.\n");
        }

        else if (strncmp(command, "calloc", 6) == 0)
        {
            size_t n, size;
            if (sscanf(command + 7, "%zu %zu", &n, &size) != 2)
            {
                printf("Usage: calloc NUM SIZE\n");
                continue;
            }
            void* ptr = my_calloc(n, size);
            int index = store_ptr(ptr);
            if (index >= 0) printf("Callocated %zu x %zu bytes at index %d (%p)\n", n, size, index, ptr);
            else printf("Calloc failed or pointer array is full.\n");
        }

        else if (strncmp(command, "realloc", 7) == 0)
        {
            int index;
            size_t size;
            if (sscanf(command + 8, "%d %zu", &index, &size) != 2)
            {
                printf("Usage: realloc INDEX SIZE\n");
                continue;
            }
            realloc_ptr_index(index, size);
        }

        else if (strncmp(command, "free", 4) == 0)
        {
            int index;
            if (sscanf(command + 5, "%d", &index) != 1)
            {
                printf("Usage: free INDEX\n");
                continue;
            }
            free_ptr_index(index);
        }

        else if (strcmp(command, "print") == 0) print_state();

        else if (strcmp(command, "exit") == 0) break;

        else printf("Unknown command.\n");
    }

    //Clean the heap before exiting
    for (int i = 0; i < MAX_PTRS; i++) 
    {
        if (user_ptrs[i]) {
            my_free(user_ptrs[i]);
            user_ptrs[i] = NULL;
        }
    }

    return 0;
}
