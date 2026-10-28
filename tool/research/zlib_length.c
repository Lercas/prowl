/* Deterministic compression-length oracle. No scanner input is executable code. */
#include "zlib.h"
#include <string.h>

static unsigned char input[1048576];
static unsigned char output[1050000];

unsigned char *input_ptr(void) { return input; }
unsigned long input_limit(void) { return sizeof(input); }

unsigned long compressed_len(unsigned long length) {
    if (length == 0 || length > sizeof(input)) return 0;
    unsigned long size = sizeof(output);
    int result = compress2(output, &size, input, length, 6);
    memset(input, 0, length);
    memset(output, 0, size <= sizeof(output) ? size : sizeof(output));
    return result == Z_OK ? size : 0;
}
