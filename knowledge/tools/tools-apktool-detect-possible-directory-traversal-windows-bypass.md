---
id: tools-apktool-detect-possible-directory-traversal-windows-bypass
title: Apktool 路径穿越修复在 Windows 上被正斜杠绕过：detectPossibleDirectoryTraversal 只查反斜杠，资源名用 ../ 仍任意写文件
type: scenario
domain: tools
path: tools
technique: apktool-directory-traversal-check-windows-separator-bypass
aliases:
- GHSA-vgwr-4w3p-xmjv
- Apktool 修复绕过
- detectPossibleDirectoryTraversal 绕过
- Windows 正斜杠路径穿越
- CVE-2024-21633 绕过
tags:
- apktool
- android
- reverse-engineering
- tool-vulnerability
- path-traversal
- windows
- separator-bypass
- arbitrary-file-write
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: 2.9.2（原文复现版本；GHSA-vgwr-4w3p-xmjv）
verification:
  verified_by: verifier-V592
  verified_at: '2026-11-12T15:37:57+08:00'
  notes: 已对照原文/截图核对 detectPossibleDirectoryTraversal 的Windows分支只查 ..\ 与 \..、separator='/'、2.9.2 Windows 解码后 poc 逃逸到 E:\temp\apktool sec(img20/22)、GHSA-vgwr-4w3p-xmjv。已修正图号21-22->22。版本按原文复现版本2.9.2标注；Linux/macOS 分支行为为代码推论，原文未实测。
---

## 一句话结论

CVE-2024-21633 的修复 `detectPossibleDirectoryTraversal` 在 Windows 上只匹配 `..\\` 与 `\\..`，但 Windows API/Java File 同时接受正斜杠；把恶意 APK 资源名改成 `../../poc`（正斜杠）即可绕过检测，Apktool 2.9.2 在 Windows 上解码时仍把文件写到输出目录之外，任意文件写入未真正修复。

## 原理

- **修复逻辑**：`BrutIO.detectPossibleDirectoryTraversal(String entry)` 按操作系统分支：
  ```java
  if (OSDetection.isWindows()) {
      return entry.contains("..\\") || entry.contains("\\..");
  }
  return entry.contains("../") || entry.contains("/..");
  ```
  命中时把 `outResName` 从恶意的 `res.getFilePath()` 换成原始 `inFileName`，跳过恶意路径。
- **缺陷**：Windows 文件系统与 Win32 API 把 `/` 与 `\` 都当作目录分隔符，Java `new File(dir, "res/../../poc")` 在 Windows 上同样逐级跳出。修复代码却假设"Windows 只用反斜杠"，正斜杠形式的 `../` 不命中黑名单，恶意 `res.getFilePath()` 原样进入输出路径拼接，穿越仍然发生。
- **为什么成立**：这是"按分隔符黑名单做安全校验"的经典坑——校验集合与实际解析方（Win32/CRT/Java）接受的语法不一致；正确做法是规范化路径后做前缀比较（canonical path startsWith 输出目录），而不是列举分隔符。
- **复现**：构造资源名 `../../poc`（正斜杠）的恶意 APK（同 CVE-2024-21633 的 resources.arsc 改法），在 Windows 上用 Apktool 2.9.2 `apktool d app-debug.apk`；解码前父目录无 `poc`，解码后 `E:\temp\apktool sec\poc` 出现（image 22），证明修复被绕过。作者因此提交 GHSA-vgwr-4w3p-xmjv。

## 触发条件

- 在 Windows 上使用 Apktool 2.9.2（含 CVE-2024-21633 修复但未修正分隔符兼容）解码不可信 APK。
- 恶意 APK 的资源表资源名使用正斜杠穿越（如 `../../poc`），且不经反斜杠。
- 解码进程对输出目录之外目标路径有写权限；Web/自动化场景危害放大。
- Linux/macOS 上同一 APK 会命中 `../` 分支被拦，该绕过是 Windows 特有。

## 利用步骤

1. 以 CVE-2024-21633 同样的方法构造恶意 APK：修改 `resources.arsc` 中 raw 资源不带前缀的 Name 串为 `../../poc`（正斜杠，层级按目标路径调整）。
2. 在 Windows 主机（装有 Apktool 2.9.2）上执行 `apktool d app-debug.apk`。
3. 检查输出目录的父目录：`poc` 文件被写出（image 22 红框），穿越成功。
4. 将目标路径换成可执行的站点目录或启动项，内容换成 WebShell/脚本完成进一步利用。

## PoC

```text
# 恶意 APK: resources.arsc 中 raw 资源 Name = ../../poc（正斜杠，default 仍为 res/raw/aaaaaaaaaaaaa）
E:\temp\apktool sec> apktool --version
2.9.2
E:\temp\apktool sec> apktool d app-debug.apk
...
E:\temp\apktool sec> dir
... <DIR> .
... <DIR> ..
...  4,142,577 bytes poc     <- 解码前不存在，解码后逃逸到父目录
```

原文以 Windows 命令行实测（image 22），未给自动化脚本；PoC 未在本机执行。

## 变体与关联

- 变体：混合分隔符（`..\../`）、多级正斜杠、把反斜杠与正斜杠混写规避不同分支；目标路径改为用户目录/启动项/Web 目录。
- 关联卡片：[[tools-apktool-cve-2024-21633-resource-name-path-traversal-write]]（被绕过的原始漏洞与修复 commit）、[[tools-apktool-unknownfiles-decode-path-traversal-arbitrary-write]]（同工具旧版解包路径穿越）。

## 检测与防御

- **修复**：不要按 OS 列举分隔符；对输出路径做规范化（`getCanonicalPath`）并校验 `startsWith(outputDirCanonical + separator)`，同时拒绝绝对路径；Windows 上把 `/` 与 `\` 都视为分隔符。
- **运行时**：在 Windows 上解码不可信 APK 同样使用容器/沙箱与专用低权限账户，限制输出目录外写权限。
- **检测**：资源名含 `../`/`..\\`/混合分隔符或绝对路径；解码进程向输出目录之外写入；输出目录父级出现新文件。
