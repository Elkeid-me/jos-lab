# JOS Lab

这是北京大学 2023 年秋季《操作系统实验班》课程的实验作业。来源于 MIT 2018 年秋季 6.828 课程的 JOS Lab。

JOS 是一个运行于 IA-32 架构的操作系统，支持抢占式多任务、多处理器，并具有简易的文件系统。

Lab 框架位于 MIT 之存储库 [Index of /2018/jos.git](https://pdos.csail.mit.edu/6.828/2018/jos.git)。

本存储库包含 Lab 1 ~ Lab 5，修复了 MIT 源代码中的错误，并完成了以下挑战（Challenge）：

- Lab 1 Challenge 1：JOS 控制台的彩色输出
- Lab 2 Challenge 1：使用 4 MB 大页映射 JOS 内核空间，并且保证仅在支持大页的 IA-32 处理器上启用这一特性。
- Lab 2 Challenge 2：JOS 控制台中与虚拟内存相关的调试命令。这部分代码仅位于分支 `lab2`。不保证其正确性。
- Lab 3 Challenge 2：JOS 控制台的“继续”与“单步运行”调试命令。
- Lab 3 Challenge 3：使用 `sysenter` 与 `sysexit` 指令实现快速系统调用。
- Lab 4 Challenge 3：使用 `fxrstor` 与 `fxsave` 指令进行浮点状态的保存与恢复，并编写了使用 MMX 指令集的测试代码。
- Lab 5 Challenge 2：文件系统内存缓存的驱逐机制。这部分代码比较仓促。

默认分支为 `lab5`，因为此分支包含所有代码，包括对 Lab 1 ~ Lab 4 的补丁。

相关的笔记位于：

- [Lab 1](https://elkeid-me.github.io/2023/10/08/OS-Lab-1/)
- [Lab 2](https://elkeid-me.github.io/2023/10/22/OS-Lab-2/)
- [Lab 3](https://elkeid-me.github.io/2023/11/05/OS-Lab-3/)
- [Lab 4](https://elkeid-me.github.io/2023/11/26/OS-Lab-4/)
- [Lab 4](https://elkeid-me.github.io/2023/12/17/OS-Lab-5/)

推荐倒序阅读。
