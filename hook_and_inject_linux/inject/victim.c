#include <stdio.h>
#include <unistd.h>

int main() {
    pid_t pid = getpid();

    printf("PID: %d\n", pid);

    sleep(1800);
    return 0;
}
