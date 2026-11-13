---
id: tools-apktool-unknownfiles-decode-path-traversal-arbitrary-write
title: Apktool decodeUnknownFiles 路径穿越：APK 内 unknown 文件条目名 ../../../ 逃逸输出目录任意写文件
type: scenario
domain: tools
path: tools
technique: apktool-decode-unknownfiles-path-traversal
tags:
- apktool
- android
- reverse-engineering
- tool-vulnerability
- path-traversal
- arbitrary-file-write
- zip-entry
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: < 2.2.2（原文表述；复现 commit 499c2f9039ba55c2bbc4ab7dc7b28c6e6cb78d92）
verification:
  verified_by: verifier-V592
  verified_at: '2026-11-12T15:37:35+08:00'
  notes: 已对照原文/22图核对：原文'2.2.2版本以下'表述与复现commit 499c2f9、decodeUnknownFiles copyToDir 原样拼接条目名、../../../aaa 逃逸到 temp(img07)、修复版 separator='/'+sanitizeFilepath canonical校验拦截 ..\..\aaaa(img10)。已修正步骤4图号06->07。版本按原文保留<2.2.2并注明复现commit，未猜修复区间。
url: /docs/tools/tools-apktool-unknownfiles-decode-path-traversal-arbitrary-write/
draft: false
kb_aliases:
- Apktool unknownFiles 路径穿越
- Apktool 任意文件写入
- decodeUnknownFiles
- APK 解包路径穿越
- apktool 2.2.2 目录穿越
---

## 一句话结论

Apktool 2.2.2 之前 `decodeUnknownFiles` 把 APK 中所有非标准文件按压缩包内的原始相对路径 `copyToDir` 到 `outDir/unknown`，完全不做路径清洗；攻击者在恶意 APK 里加入名为 `../../../aaa` 的条目，受害者 `apktool d` 时该文件就被写到输出目录之外，形成任意文件写入（Web 在线反编译服务中可直接落地 WebShell）。

## 原理

- **攻击面**：APK 就是 ZIP。`decodeUnknownFiles` 遍历 `apkFile.getDirectory().getFiles(true)`，对不匹配 APK 标准文件名（`isAPKFileNames`）且不以 `.dex` 结尾的条目，调用 `unk.copyToDir(unknownOut, file)` 原样复制到 `outDir/unknown` 下。
- **缺陷**：`file` 直接来自 ZIP 条目名（`ZipEntry.getName()`），攻击者可以构造含 `../` 的条目名。`copyToDir` 内部以 `new File(unknownOut, file)` 拼接路径，未做规范化/前缀校验，`../../../aaa` 逐级跳出输出目录，写到哪里取决于 apktool 进程的权限与运行目录——在线解包/自动化流水线场景可覆盖应用文件、写定时任务或 WebShell。
- **为什么当时没被拦**：过滤条件只判断"是不是 aapt 预定义的标准号文件"，不判断名称里是否含目录穿越序列；ZIP 条目名又完全由攻击者控制。
- **修复方式**：新版在 `Directory.loadAll` 增加 `name.contains(".." + separator)` 过滤（`separator='/'`，见图），并在 `sanitizeFilepath` 中做 canonical path 前缀校验：`new File(directory, entry).getCanonicalPath()` 必须 `startsWith(directory.getCanonicalPath()+File.separator)`，否则抛 `TraversalUnknownFileException` 跳过。文章实测把 payload 改成 Windows 反斜杠形式 `..\..\aaaa` 仍被第二处 canonical 校验拦截（日志 `Skipping file ..\..\aaaa`），因此旧版式穿越在修复版上不再成立。

## 触发条件

- 使用 Apktool 2.2.2 之前的版本执行 `apktool d`（或封装其解包能力的在线服务/自动化系统）。
- 攻击者可控制被解包的 APK 内容（可在 ZIP 中插入任意名称条目）。
- 运行 apktool 的进程对输出目录之外的目标路径有写权限。
- 解包结果被 Web 服务器托管/可执行时危害放大（写 shell）。

## 利用步骤

1. 生成或取一个正常 APK，作为载体。
2. 向 APK（ZIP）里追加一个条目，条目名设为 `../../../aaa`（按需增加层级和文件名，如 `../../../var/www/html/shell.jsp`），内容为任意文件内容。
3. 让受害者/在线服务对该 APK 执行 `apktool d`。
4. 文件被写到输出目录之外；文章实测 `temp/app-debug.apk.out/unknown` 之外出现了 `temp/aaa`（image 07）。
5. Web 场景下把目标路径选为可访问的 Web 目录，内容写成 JSP/PHP WebShell 等。

## PoC

原文未给脚本，最小构造方式（示意）：

```python
import zipfile
src = "normal.apk"
dst = "attack.apk"
with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
    for item in zin.infolist():
        zout.writestr(item, zin.read(item.filename))
    zout.writestr("../../../aaa", "poc-content")   # ZIP 条目名即穿越路径
```

随后执行 `apktool d attack.apk`，检查输出目录外的 `aaa` 是否出现。以上为按原文思路整理的示意，未在本机执行。

## 变体与关联

- 变体：条目名用多级 `../` 改写其它目录文件；压缩包内同时放正常文件降低怀疑；Windows 上用 `..\..\`（旧版同样穿越，但新版 canonical 校验会拦截）。
- 关联卡片：[[tools-apktool-cve-2024-21633-resource-name-path-traversal-write]]（新版本另一处资源名路径穿越）、[[tools-apktool-detect-possible-directory-traversal-windows-bypass]]（修复后 Windows 分隔符兼容性绕过）。

## 检测与防御

- **升级**：使用包含 `sanitizeFilepath` canonical 校验的 Apktool 版本。
- **运行时**：把 apktool 解包放在容器/沙箱与受限目录中运行，输出目录单独挂载，避免进程对系统敏感路径可写；在线反编译服务对提交的 APK 先做条目名审计。
- **检测**：APK 中存在含 `../`、`..\`、绝对路径的 ZIP 条目名即高度可疑（可用 `zipinfo`/脚本扫描）；解包进程出现向输出目录之外的写入（auditd/文件完整性监控）；Web 目录出现新落地的可执行文件。
