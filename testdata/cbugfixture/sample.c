#include <string.h>
#include <stdlib.h>

void handle(const char *src, const char *cmd) {
    char buf[16];
    strcpy(buf, src);   /* unbounded copy */
    system(cmd);        /* shell exec */
}
