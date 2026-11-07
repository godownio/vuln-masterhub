---
id: code-analysis-reverse-windows-ntuser-getclipboarddata-localmemhandle-read
title: 未文档化 win32u 剪贴板读取：NtUserGetClipboardData 取句柄 + NtUserCreateLocalMemHandle 复制 UNICODETEXT
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: ntuser-getclipboarddata-localmemhandle-read
aliases:
- NtUserGetClipboardData
- NtUserCreateLocalMemHandle
- win32u 剪贴板
- 读取当前剪贴板文本
- CF_UNICODETEXT 句柄复制
- GetClipboardData 底层实现
tags:
- windows
- win32u
- clipboard
- user32
- win32k
- reverse
- data-extraction
- undocumented-api
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:50+08:00'
  notes: 已对照原文与 43 张图片核对；NtUser* 调用与 CreateLocalMemHandle 代码一致；未在目标机复现
---

## 一句话结论

在交互式 Windows 会话中，调用 `OpenClipboard(NULL)` 后直接使用 `win32u.dll` 导出的 `NtUserGetClipboardData(CF_UNICODETEXT, &gcd)` 取得剪贴板数据句柄，再用 `NtUserCreateLocalMemHandle(hMem, NULL, 0, &size)` 探出长度、二次调用把数据复制到用户缓冲区，即可读取当前剪贴板中的 Unicode 文本，全程不依赖 `user32!GetClipboardData`/`GlobalLock` 的常规路径。

## 原理

- **调用链**：`user32!GetClipboardData` → `win32u!NtUserGetClipboardData` → 内核 `win32kfull!NtUserGetClipboardData` → `xxxGetClipboardData` → `FindClipFormat` 遍历 `WINDOWSTATION->pClipBase` 的 `CLIP` 数组（`fmt` + `hData` + `fGlobalHandle`），返回文本数据的句柄与格式。
- **句柄到内存**：`NtUserCreateLocalMemHandle(hMem, outBuf, size, &written)` 在 win32k 中先 `HMValidateHandle(hMem, 6)` 把句柄转成对象指针，再读取对象 `+0x10` 处的数据长度、`+0x14` 处的数据内容，`memmove` 到用户提供的缓冲区。因此只要拿到剪贴板数据句柄，就能用该 API 把内容复制到三环。
- **长度探测**：第一次调用传 `outBuf=NULL, size=0`，内核返回 `0xC0000023`（`STATUS_BUFFER_TOO_SMALL`）并在 `written` 中写入所需大小；按该大小 `GlobalAlloc` 后再调用一次即可。
- **格式**：`CF_UNICODETEXT=13`，数据是 UTF-16LE 字符串（可能带结尾 `\0`）；`gcd.uFmtRet` 返回实际格式，`gcd.fGlobalHandle` 表示是否为全局句柄（文本为真）。
- **为什么可行**：`OpenClipboard` 只要求当前会话/窗口站有剪贴板访问权；拿到打开权后，未文档化的 `NtUser*` 导出仍是普通用户态可调用的系统调用封装，不需要驱动或内核权限。

## 触发条件

- 目标为交互式 Windows 会话（有 `WinSta0`/桌面），当前剪贴板中有文本。
- 进程能成功 `OpenClipboard(NULL)`（没有其他进程长期占用剪贴板）。
- `win32u.dll` 导出 `NtUserGetClipboardData`、`NtUserCreateLocalMemHandle`（Windows 10/11 均存在，名称可能随版本变化）。
- 调用进程与剪贴板属主在同一会话；跨会话/服务会话读取会失败。

## 利用步骤

1. `LoadLibraryW(L"win32u.dll")`，`GetProcAddress` 取 `NtUserGetClipboardData` 与 `NtUserCreateLocalMemHandle`。
2. `OpenClipboard(NULL)` 打开剪贴板；构造 `GETCLIPBDATA gcd = {0}`。
3. `hMem = NtUserGetClipboardData(CF_UNICODETEXT, &gcd)`；若 `hMem` 为空或 `gcd.fGlobalHandle` 为假，检查格式/剪贴板是否为空。
4. 第一次 `NtUserCreateLocalMemHandle(hMem, NULL, 0, &size)`，期望返回 `0xC0000023` 并得到 `size`。
5. `GlobalAlloc(0, size)` 分配用户缓冲区，再次调用 `NtUserCreateLocalMemHandle(hMem, buf, size, NULL)` 完成复制；返回 `>=0` 即成功。
6. `CloseClipboard()`，把缓冲区按 `wchar_t*` 输出/保存；注意长度与结尾 `\0`。

## PoC

```cpp
#include <windows.h>
#include <iostream>

typedef struct tagGETCLIPBDATA {
    UINT uFmtRet;
    BOOL fGlobalHandle;
    union { HANDLE hLocale; HANDLE hPalette; };
} GETCLIPBDATA, *PGETCLIPBDATA;

typedef HANDLE(NTAPI* pNtUserGetClipboardData)(UINT fmt, PGETCLIPBDATA pgcd);
typedef NTSTATUS(APIENTRY* pNtUserCreateLocalMemHandle)(
    HANDLE hMem, LPVOID pData, DWORD64 cbData, DWORD* pcbData);

int wmain() {
    HMODULE win32u = LoadLibraryW(L"win32u.dll");
    auto NtUserGetClipboardData =
        (pNtUserGetClipboardData)GetProcAddress(win32u, "NtUserGetClipboardData");
    auto NtUserCreateLocalMemHandle =
        (pNtUserCreateLocalMemHandle)GetProcAddress(win32u, "NtUserCreateLocalMemHandle");

    if (!OpenClipboard(NULL)) return 1;
    GETCLIPBDATA gcd = {0};
    HANDLE hMem = NtUserGetClipboardData(13 /* CF_UNICODETEXT */, &gcd);
    if (!hMem || !gcd.fGlobalHandle) { CloseClipboard(); return 2; }

    DWORD size = 0;
    if (NtUserCreateLocalMemHandle(hMem, NULL, 0, &size) != 0xC0000023) {
        CloseClipboard(); return 3;
    }
    HGLOBAL buf = GlobalAlloc(0, size);
    if (!buf || NtUserCreateLocalMemHandle(hMem, buf, size, NULL) < 0) {
        CloseClipboard(); return 4;
    }
    CloseClipboard();
    std::wcout << (wchar_t*)buf << std::endl;   // UTF-16 文本
    GlobalFree(buf);
}
```

```text
# 实测：复制 "1,2,3,4,5,6..." 后运行，缓冲区读到对应 UTF-16 文本。
# 若只读当前剪贴板历史，需要对 cbdhsvc 进程内存做提取（见关联卡）。
```

## 变体与关联

- 变体：正常路径 `GetClipboardData(CF_UNICODETEXT)` + `GlobalLock` 也能读文本，但某些场景（句柄类型/延迟渲染/自定义格式）绕过用户态封装更直接。
- 变体：`CF_DIB`/`CF_HDROP`/自定义格式同样可先取 `hData` 再用 `NtUserCreateLocalMemHandle` 复制；格式号可枚举 `EnumClipboardFormats`。
- 变体：若目标进程在服务会话/不同窗口站，`OpenClipboard` 失败；可改用 `NtUserOpenClipboard`/窗口站切换（需相应权限）。
- 关联：[[code-analysis-reverse-windows-cbdhsvc-clipboard-history-vtable-memory-scan]]（读取 25 条剪贴板历史，而非当前内容）、[[defense-forensics-terminal-osc52-clipboard-read]]（终端 OSC 52 读取宿主机剪贴板）。
- 边界：`OpenClipboard` 可能被其他程序占用；受保护进程/跨会话不可读；`NtUser*` 是未文档化接口，版本间行为可能变化。

## 检测与防御

- 检测：监控对 `win32u!NtUserGetClipboardData`/`NtUserCreateLocalMemHandle` 的调用；剪贴板读取后立即外联/落盘的行为；EDR 对 `OpenClipboard` + 非 UI 进程组合告警。
- 防御（用户/企业）：不要用剪贴板传递密码、令牌、私钥；启用剪贴板历史前评估隐私风险；用密码管理器替代复制粘贴。
- 加固：应用层对敏感数据使用受控信道；EDR 限制同用户进程的剪贴板访问与内存读取；禁用不必要的剪贴板历史/云同步。
