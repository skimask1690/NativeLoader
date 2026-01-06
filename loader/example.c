#include "pe_loader.h"

__attribute__((section(".text")))
unsigned char pe_blob[] = { /* x64 native PE bytes go here */ };

__attribute__((section(".text.start")))
void _start(void) {
    ExecuteFromMemory(pe_blob);
}
