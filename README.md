# hook_and_inject_linux

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


