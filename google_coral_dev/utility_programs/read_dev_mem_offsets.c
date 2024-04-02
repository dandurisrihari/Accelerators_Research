#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define PAGE_SIZE 4096 // System page size, use sysconf(_SC_PAGESIZE) in a real application

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <operation: read|write|dump> <base address> <offset> [value to write|size to dump]\n", argv[0]);
        return 1;
    }

    char* operation = argv[1];
    unsigned long base_address = strtoul(argv[2], NULL, 0);
    unsigned long offset = strtoul(argv[3], NULL, 0);
    uint32_t value_to_write = 0;
    size_t size_to_dump = 0;

    if (strcmp(operation, "write") == 0 && argc == 5) {
        value_to_write = (uint32_t)strtoul(argv[4], NULL, 0);
    } else if (strcmp(operation, "dump") == 0 && argc == 5) {
        size_to_dump = (size_t)strtoul(argv[4], NULL, 0);
    }

    // Adjust size_to_dump for read operation
    if (strcmp(operation, "read") == 0) {
        size_to_dump = sizeof(uint32_t); // For reading a single 32-bit value
    }

    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1) {
        perror("Error opening /dev/mem");
        return 1;
    }

    // Align base address to page boundary and adjust map size accordingly
    off_t aligned_base_address = base_address & ~(PAGE_SIZE - 1);
    size_t aligned_offset = offset + (base_address - aligned_base_address);
    size_t map_size = (aligned_offset + size_to_dump + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    void* map_base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, aligned_base_address);
    if (map_base == MAP_FAILED) {
        perror("Error mapping memory");
        close(fd);
        return 1;
    }

    void* addr = (void*)((char*)map_base + aligned_offset);

    if (strcmp(operation, "read") == 0) {
        uint32_t value;
        memcpy(&value, addr, sizeof(value));
        printf("Value at 0x%lX (offset 0x%lX): 0x%X\n", base_address + offset, offset, value);
    } else if (strcmp(operation, "write") == 0) {
        memcpy(addr, &value_to_write, sizeof(value_to_write));
        printf("Written 0x%X to 0x%lX (offset 0x%lX)\n", value_to_write, base_address + offset, offset);
    } else if (strcmp(operation, "dump") == 0) {
        printf("Dumping %zu bytes from 0x%lX (offset 0x%lX):\n", size_to_dump, base_address + offset, offset);
        for (size_t i = 0; i < size_to_dump; ++i) {
            printf("%02X ", *((unsigned char*)addr + i));
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        if (size_to_dump % 16 != 0)
            printf("\n");
    }

    munmap(map_base, map_size);
    close(fd);

    return 0;
}
