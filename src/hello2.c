#include <stdio.h>
#include "libs1.h"
#include "libd1.h"

int main() {
    printf("Hello world\n");
    int a = print_s1_info();
    int b = print_d1_info();
    printf("a=%d b=%d\n", a, b);
    return 0;
}
