---
id: code-analysis-reverse-anti-debug-getcurrentdirectoryw-root-trailing-backslash
title: 反沙箱路径陷阱：GetCurrentDirectoryW 仅在盘符根目录返回尾随反斜杠，%s 直接拼接文件名使子目录中的样本提前退出
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: getcurrentdirectoryw-root-trailing-backslash-sandbox-evasion
tags:
- anti-debug
- anti-sandbox
- windows
- path-construction
- evasion
- malware
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T11:46:02+08:00'
  notes: 已对照原文与图01/02/16核对：GetCurrentDirectoryW(260) -> swprintf_s("%s邀请函回执.docx")，子目录得 C:\Users\admin\Desktop\1邀请函回执.docx，根目录得 C:\邀请函回执.docx；GetFileAttributesW 失败或目录属性则跳过 ShellExecuteW。图01/02 的调试器内存与磁盘路径一致，图05/06 沙箱进程树显示解压目录运行。未验证点：作者对“故意设计”的判断不确定；未复跑；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-getcurrentdirectoryw-root-trailing-backslash/
draft: false
kb_aliases:
- GetCurrentDirectoryW 尾随反斜杠
- 根目录路径拼接反沙箱
- 路径构造反沙箱
- 子目录提前退出
---

## 一句话结论

样本用 `GetCurrentDirectoryW` 取当前目录后直接用 `%s邀请函回执.docx` 这种不带分隔符的格式拼接路径：该 API 在盘符根目录（如 `C:\`）返回带尾随反斜杠的字符串，在普通子目录（如 `C:\Users\admin\Desktop\1`）不返回尾随反斜杠；于是只有从根目录运行才能拼出有效路径，沙箱把 IMG 解压到子目录运行时会得到 `...\1邀请函回执.docx`，`GetFileAttributesW` 失败后样本直接退出，后续注入与外联都不会发生。

## 原理

- Win32 `GetCurrentDirectoryW` 返回进程当前目录。若当前目录是盘符根目录（`C:\`、`E:\`），返回字符串以 `\` 结尾；若当前目录是子目录（`C:\Users\admin\Desktop\1`），返回字符串不以 `\` 结尾，这是该 API 的正常行为。
- 样本先用 `GetCurrentDirectoryW(260, Buffer)` 把当前目录写进缓冲区，随后用 `swprintf_s(Buffer, 0x104, L"%s邀请函回执.docx", Buffer)` 之类的格式直接拼接文件名，格式串中没有 `\` 分隔符。
- 在根目录运行时结果为 `C:\邀请函回执.docx`，路径有效；在子目录运行时结果为 `C:\Users\admin\Desktop\1邀请函回执.docx`，文件名被粘到目录名后面，路径不存在。截图中的两次构造分别显示了这两个结果。
- 拼接后样本调用 `GetFileAttributesW` 检查路径；返回 `INVALID_FILE_ATTRIBUTES` 时跳过 `ShellExecuteW` 并让当前模式返回失败，调用方随即退出，不进入进程注入、文件拷贝、注册表自启动或 shellcode 外联阶段。
- 该行为与显式的沙箱检测 API、时间加速检测、VM 工件查询都不同：它只依赖“当前目录是否为盘符根目录”，没有明显的高敏感查询。正常使用场景是把 `.img` 双击挂载为虚拟光驱，再从光驱根目录运行 LNK，当前目录就是 `E:\`，路径成立；多数沙箱选择解压镜像后从工作子目录运行，路径不成立，于是样本“什么都没做就退出”。
- 这类门控的隐蔽性在于：它看起来像路径拼接缺陷，静态分析容易忽略；只有在根目录执行才会走到真正的恶意逻辑，自动化沙箱拿不到后续行为，查杀率因此偏低。

## 触发条件

- 目标为 Windows，样本以当前目录为盘符根目录的方式启动（挂载后的虚拟光驱根目录、直接放在 `C:\` 根目录等）。
- 根目录下存在与拼接文件名同名的诱饵文档（如 `邀请函回执.docx`），否则即使路径拼接正确也会因文件不存在而退出。
- 当前目录为任意子目录时，拼接结果缺少分隔符，`GetFileAttributesW` 失败，样本提前退出。
- 沙箱/分析平台如果采用“解压镜像到工作目录再执行”的方式，就会落入失败分支；如果采用真实挂载并从根目录执行，则可能看到后续行为。

## 利用步骤

1. 把 loader、诱饵文档一起放在镜像根目录（或任意盘符根目录）；用 `.img`/`.iso` 承载，双击由系统挂载为虚拟光驱。
2. 从光驱根目录运行 LNK/loader，使 `GetCurrentDirectoryW` 返回带尾随反斜杠的 `E:\`。
3. loader 调用 `GetCurrentDirectoryW`，用 `%s` + 文件名直接拼接；根目录下得到 `E:\邀请函回执.docx`，`GetFileAttributesW` 成功。
4. 打开诱饵文档作为掩护，随后进入注入、持久化与二阶段执行。
5. 若在子目录运行，拼接结果变成 `<目录><文件名>`，属性查询失败，loader 返回失败并退出；沙箱因此只能记录到一次快速退出。
6. 防御性复现时可在测试机创建两种当前目录，分别观察 `GetCurrentDirectoryW` 的返回值是否带尾随反斜杠，以及后续路径是否有效。

## PoC

路径构造逻辑的最小示例（安全演示，不包含恶意载荷）：

```c
#include <windows.h>
#include <stdio.h>

int main(void) {
    WCHAR dir[MAX_PATH] = {0};
    WCHAR path[MAX_PATH] = {0};

    GetCurrentDirectoryW(MAX_PATH, dir);
    swprintf_s(path, MAX_PATH, L"%s邀请函回执.docx", dir);

    wprintf(L"cwd  = %ls\n", dir);
    wprintf(L"path = %ls\n", path);

    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
        return 0;  // 子目录：路径无效，提前退出

    ShellExecuteW(NULL, L"open", path, NULL, NULL, SW_SHOWNORMAL);
    return 0;
}
```

在 `C:\` 下运行与在 `C:\Users\admin\Desktop\1` 下运行，`path` 分别为 `C:\邀请函回执.docx` 与 `C:\Users\admin\Desktop\1邀请函回执.docx`。

## 变体与关联

- 变体：用 `GetModuleFileNameW` 取完整模块路径后 `PathRemoveFileSpec` 再去拼接，同样可能因分隔符处理不当产生路径差异。
- 变体：显式检查当前目录是否等于某个盘符根目录（`GetDriveTypeW`、路径长度与结尾字符判断），命中才继续；比隐式拼接更可控。
- 变体：把判断条件换成“当前目录下是否存在诱饵文件”“当前目录是否可写”等环境键控。
- 关联：`code-analysis-reverse-anti-debug-sandbox-environment-checks`（时间加速、桌面文件数、用户名/主机名、DebugPort 等常规反沙箱检查）、`code-analysis-reverse-anti-debug-visual-environmental-keying-screenshot`（截屏像素环境键控）、`code-analysis-reverse-anti-debug-silverfox-installer-vm-detection`（VM 工件检测）。本卡是“路径/当前目录”维度的门控，不依赖 API hook 或 VM 工件。
- 注意：原文作者起初认为这是样本 BUG；从行为看它确实只在根目录成立，但不能仅凭此证明作者有意设计。卡片按“可观察到的环境门控”记录，意图判断标注为不确定。

## 检测与防御

- 沙箱/分析平台：不要只解压镜像；优先真实挂载 `.img`/`.iso` 并从根目录启动样本，或把工作目录设置为盘符根目录后重试，观察是否出现后续行为。
- 动态检测：监控 `GetCurrentDirectoryW` → `swprintf_s`/`wsprintf` → `GetFileAttributesW` 的连续调用，以及属性查询失败后立即退出的模式；对“入口后很快退出且无网络/文件行为”的样本尝试多目录重放。
- 静态检测：检查格式串中 `%s` 后是否直接跟文件名而缺少 `\`，尤其是拼接后紧接 `GetFileAttributesW`/`ShellExecuteW` 的代码；把“路径构造依赖 cwd 结尾字符”的样本标记为环境敏感。
- 防御：在沙箱中模拟根目录运行、增加对镜像挂载执行的覆盖率；对样本做多轮不同 cwd 的执行并比较行为差异；结合进程树中父进程的 cwd 与 LNK 目标路径判断是否来自挂载点根目录。
