#include <cstring>
#include <cstdlib>

void run(const char *src) {
    char buf[16];
    sprintf(buf, "%s", src);   // unbounded format
}
