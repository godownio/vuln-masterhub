---
id: code-analysis-reverse-windows-silverfox-autoit-fileinstall-libcef-webprocess-sideload
title: 银狐 AutoIt FileInstall 落盘：webprocess.exe 侧加载 libcef.dll → 硬编码数据解密 → 内存映射调 JeffcEn
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silverfox-autoit-fileinstall-libcef-webprocess-sideload
tags:
- windows
- malware-analysis
- silverfox
- autoit
- fileinstall
- dll-sideload
- libcef
- self-delete
- c2
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V423
  verified_at: '2026-11-09T16:54:42+08:00'
  notes: 已对照原文与32张图核对：AutoIt3 stub/#RequireAdmin/DirCreate(@SystemDir\xq)/两条FileInstall(libcef.dll+webprocess.exe,0x0)/Run/Sleep(100)轮询ProcessList/FileDelete+DirRemove(图19-20)、webprocess.exe导入libcef导出(图22)、libcef.dll约1.3MB DIE 2024-04-28、解密循环→内存MZ(0x10008050)(图25-26)、VirtualAlloc+跳转payload入口→调用JeffcEn、C2 156.237.223.130(图28-31)均一致。小瑕疵：DIE的NSIS 2.46.5特征出现在libcef.dll(0x153000≈1.3MB)，卡内检测段'webprocess.exe的NSIS特征'归因错位，建议改为libcef.dll；'宿主签名'原文未证实。未验证点：PoC未执行、硬编码数据解密算法原文未展开。无sources/文章ID/长段摘录，路径合法；dedup候选(inno-dlclr/autoit3-a3x/cef-helper等)非同链；dup-scan(11-08 19:10)早于建卡无涉及pair。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-silverfox-autoit-fileinstall-libcef-webprocess-sideload/
draft: false
kb_aliases:
- 银狐 AutoIt 白加黑
- webprocess.exe libcef.dll
- FileInstall 释放载荷
- 自删除加载器
- JeffcEn 导出
- 硬编码数据解密
---

## 一句话结论

银狐样本三是 AutoIt 编译的释放器：脚本 `#RequireAdmin`，`DirCreate(@SystemDir & "\xq")` 后用 `FileInstall` 把内嵌的 `libcef.dll`（约 1.3MB）与 `webprocess.exe`（388KB）释放到 `%SystemDir%\xq`，`Run` 启动 `webprocess.exe` 后轮询进程，退出即 `FileDelete` 两文件并清理目录；`webprocess.exe` 从同目录侧加载恶意 `libcef.dll`，后者解密硬编码数据得到 PE，`VirtualAlloc` 写入并跳转入口，最终调用导出 `JeffcEn`，内存中出现 C2 `156.237.223.130`。

## 原理

- **AutoIt 编译脚本作为释放器**：样本由 AutoIt3 编译（DIE 识别 `AutoIt3(3.XX)[-]`、`AutoIt compiled script(2.XX-3.XX)[-]` 覆盖层）。脚本用 `FileInstall(源, 目标, 0x0)` 把编译时内嵌的文件写到目标路径，相当于一个自带解包器的签名/常见运行时宿主；`#RequireAdmin` 让脚本请求管理员权限，`DirCreate` 创建 `%SystemDir%\xq`（`C:\Windows\SysWOW64\xq` 一类路径）。
- **启动与自删除**：`Run('"C:\Windows\SysWOW64\xq\webprocess.exe"', ..., @SW_SHOW)` 启动白程序；随后 `ProcessList("webprocess.exe")` 轮询，进程退出后 `FileDelete` 删除 `libcef.dll` 与 `webprocess.exe`，`DirGetSize` 为 0 时 `DirRemove` 删除目录——实现“运行后不留文件”的清理，增加磁盘取证难度。
- **白加黑侧加载**：`webprocess.exe` 是白宿主，从自身目录按名称加载 `libcef.dll`；恶意 `libcef.dll` 导出 CEF 相关函数（如 `api_hash`、`base64decode`、`base64encode` 等）以满足宿主导入表，避免因缺少导出启动失败。宿主的签名/文件名与 libcef 的正常用途提供掩护。
- **硬编码数据解密**：`libcef.dll` 的恶意逻辑在内存中解密自身硬编码数据块（x64dbg 中可见逐字节解密循环），解密后出现完整 `MZ`/PE 结构（内存地址约 `0x10008050`）；具体算法/密钥文章未展开，需动态调试确认。
- **内存映射与入口调用**：解密后的 PE 通过 `VirtualAlloc` 分配内存、拷贝镜像，跳到 payload 模块入口代码执行；随后调用 payload 的导出函数 `JeffcEn`（x64dbg 栈与 IDA 交叉引用均可看到 `JeffcEn`），C2 字符串 `156.237.223.130` 在同一内存区域出现。
- **与样本一的关联**：样本一的 Gh0st `Server.dll` 也导出 `JeffcEn`，说明两条投递链复用同一核心载荷/家族代码，只是外层包装不同（HTTP 下载器 vs AutoIt+libcef 白加黑）。

## 触发条件

- 受害者运行 AutoIt 编译的释放器（钓鱼包/下载器释放），并同意/绕过 UAC 获得管理员权限（`#RequireAdmin`）。
- 目标目录 `%SystemDir%\xq` 可创建、`webprocess.exe` 可从该目录启动；`libcef.dll` 的导出能满足宿主导入。
- 进程允许分配/执行内存；C2 可达。
- 分析侧：需要 AutoIt 样本与隔离环境；硬编码数据解密算法未在文中给出，需动态调试 dump。

## 利用步骤

1. 用 DIE 识别 AutoIt 编译样本，提取内嵌 AutoIt 脚本（`Exe2Aut`/`myAut2Exe` 一类工具）。
2. 审阅脚本：`#RequireAdmin`、`DirCreate(@SystemDir & "\xq")`、两条 `FileInstall`、`Run`、`ProcessList` 轮询、`FileDelete`/`DirRemove` 自删除逻辑。
3. 从 AutoIt 资源或运行目录提取 `libcef.dll`（约 1.3MB，2024-04-28 编译）与 `webprocess.exe`（388KB）；确认 `webprocess.exe` 的导入表依赖 `libcef.dll` 的 CEF 导出。
4. x64dbg 附加 `webprocess.exe`，在 `libcef.dll` 的解密循环与 `VirtualAlloc` 处下断；解密完成后 dump 内存中的 PE。
5. 跟随执行到 payload 入口，定位导出 `JeffcEn` 的调用与 C2 字符串 `156.237.223.130`。
6. 把 AutoIt 释放路径 `%SystemDir%\xq`、文件哈希、`JeffcEn` 导出与 C2 作为 IOC，与样本一关联。

## PoC

```text
AutoIt 脚本关键逻辑（整理自反编译/提取）：
  #RequireAdmin
  DirCreate(@SystemDir & "\xq")
  FileInstall("...\libcef.dll",    @SystemDir & "\xq\libcef.dll", 0)
  FileInstall("...\webprocess.exe", @SystemDir & "\xq\webprocess.exe", 0)
  Run('"' & @SystemDir & "\xq\webprocess.exe" & '"', @SystemDir & "\xq")
  Do
      Sleep(100)
      $pid = ProcessList("webprocess.exe") ...
  Until $pid = ""
  FileDelete(@SystemDir & "\xq\libcef.dll")
  FileDelete(@SystemDir & "\xq\webprocess.exe")
  DirRemove(@SystemDir & "\xq")
```

```text
动态观察点：
  libcef.dll 解密循环 -> 内存 MZ/PE（约 0x10008050）
  VirtualAlloc + 拷贝 + 跳转 payload 入口
  调用导出 JeffcEn；内存字符串 156.237.223.130
```

## 变体与关联

- `%SystemDir%\xq` 目录名、宿主名（webprocess.exe）与载荷名（libcef.dll）可按样本替换；核心手法是“AutoIt FileInstall 释放 + 白加黑 + 自删除”。
- 与既有 CEF Helper 白加黑卡的区别：本卡宿主是 NSIS/自定义 `webprocess.exe`，外层是 AutoIt 释放器并自删除，载荷导出 JeffcEn；既有卡是 JetBrains CEF Helper + 512MB 文件膨胀 + 服务持久化。
- 关联：[[code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation]]（另一条 libcef 侧加载链）、[[pentest-c2-autoit3-a3x-interpreter-payload-host]]（AutoIt3 解释器 + a3x 载荷宿主）、[[code-analysis-reverse-windows-silverfox-upx-http-txt-downloader-gh0st-memory]]（同篇下载器链，共享 JeffcEn 载荷）。
- 边界：AutoIt 编译版本/提取工具差异可能影响脚本还原；硬编码数据解密算法未还原时无法离线得到 payload；`#RequireAdmin` 被 UAC 拒绝则释放失败。

## 检测与防御

- **主机**：监控 `C:\Windows\SysWOW64\` 下新建 `xq` 类目录与 `webprocess.exe`/`libcef.dll` 组合；AutoIt 编译样本（DIE 特征）释放文件后自删除；`VirtualAlloc` + 跳转 + 调用 `JeffcEn` 导出。
- **文件**：对 `libcef.dll` 做签名/哈希比对，检查其导出是否与宿主导入一致但函数体异常；`webprocess.exe` 的 NSIS/伪装特征。
- **终端**：限制普通用户写 `%SystemDir%`；UAC 默认拒绝未知程序提权；EDR 覆盖 AutoIt 进程的 `FileInstall`/`Run`/`FileDelete` 行为链。
- **取证**：保留下载/释放目录、AutoIt 脚本、`libcef.dll`、`webprocess.exe` 与内存 dump；按 `JeffcEn` 与 C2 关联样本一及同族。
