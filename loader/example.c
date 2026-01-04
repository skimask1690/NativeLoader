#include "pe_loader.h"

__attribute__((section(".text")))
unsigned char pe_blob[] = { /* x64 native PE bytes go here */ };

unsigned int pe_blob_len = sizeof(pe_blob);

__attribute__((section(".text.start")))
void _start(void) {
    ExecuteFromMemory(pe_blob);
}
