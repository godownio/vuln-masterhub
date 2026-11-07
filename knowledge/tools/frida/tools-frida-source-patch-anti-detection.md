---
id: tools-frida-source-patch-anti-detection
title: Frida 源码魔改反检测：重命名进程/符号/线程/memfd/RPC 特征并编译 Android arm64 server
type: scenario
domain: tools
path: tools/frida
technique: frida-source-patch-anti-detection
aliases:
- Frida 魔改
- Frida 反检测
- frida-server 定制编译
- frida_agent_main 重命名
- memfd 特征隐藏
- RPC 字符串混淆
tags:
- frida
- anti-detection
- android
- source-patch
- build
- memfd
- rpc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:11:48+08:00'
  notes: 已对照原文与8张图核对：Frida 16.2.1 源码编译、NDK r25c/lief、gum.c/mapper.c/agent-container.vala/frida-helper-backend.vala/server.vala/rpc.vala 各处 patch、topatch.py 符号与 .rodata 反转、embed-agent.sh.patch 调用链、ninja -C build 增量编译、编译日志与产物均与原文/截图一致。版本处理：Frida 16.2.1 是原文编译源码版本而非受影响版本，已清空 affected_versions（正文保留）。未验证点：本库未实际编译/运行定制 frida-server，反检测效果未实测；frontmatter 无 sources/source_url。
---

## 一句话结论

Frida 在目标进程中留下大量可检测特征（进程名 `frida`、导出符号 `frida_agent_main`、`memfd` 名称、`re.frida.server` 目录、`frida:rpc` 字符串、`FridaScriptEngine`/`GumScript` 等 `.rodata` 字符串、`gum-js-loop`/`gmain`/`gdbus` 线程名）；从源码编译 Frida 16.2.1 并逐项重命名/混淆这些特征，再重新编译 Android arm64 的 `frida-server`，可显著降低被静态字符串/符号/线程名检测发现的概率。

## 原理

- Frida 的检测面主要分四类：
  1. **进程/文件特征**：`g_set_prgname("frida")` 设置的进程名、`re.frida.server` 临时目录、`memfd_create` 的匿名文件名。
  2. **符号特征**：`frida_agent_main` 导出符号、ELF 符号表中含 `frida`/`FRIDA` 的符号。
  3. **字符串特征**：`.rodata` 中的 `FridaScriptEngine`、`GLib-GIO`、`GDBusProxy`、`GumScript`，以及 RPC 协议字符串 `frida:rpc`。
  4. **线程名特征**：`gum-js-loop`、`gmain`、`gdbus` 等运行时线程名。
- 这些特征分布在 `frida-gum`（底层 Hook/内存）、`frida-core`（进程管理/脚本加载/通信）与 `frida-agent`（注入到目标进程的 so）中；只改一处不够，需要同时改源码、ELF 符号表、`.rodata` 与嵌入流程。
- 源码编译流程：`make -f Makefile.sdk.mk ARCH=arm64` 构建 SDK，`make core-android-arm64 FRIDA_HOST=android-arm64` 构建 Android arm64 组件；`embed-agent.sh` 在把 `frida-agent-64.so` 嵌入 `frida-server` 之前调用 `topatch.py`，因此 `topatch.py` 能改到最终 agent blob。
- 修改函数核心逻辑（而非仅改字符串）会破坏 patch 的行号/上下文，导致 `git apply` 报 `hunk FAILED`；此时应直接改源码并用 `ninja -C build` 增量编译。
- 检测方若只做静态字符串/符号匹配，改名即可绕过；若做行为/系统调用/内存扫描，仍需进一步隐藏（如更深的 RPC 字符串混淆、随机化、避免固定模式）。

## 触发条件

- 目标 APP/游戏使用 Frida 检测（扫描 `/proc/self/maps`、进程名、线程名、ELF 符号、`memfd`、`frida:rpc` 字符串、`FridaScriptEngine` 等）。
- 测试者能自行编译 Frida（Ubuntu、NDK、Python、Node.js、build-essential）。
- 需要长期使用 Frida 且不想被固定特征命中。
- 目标未使用无法绕过的 native RASP/反调试/完整性校验。

## 利用步骤

1. **准备环境**：Ubuntu + git + Android NDK r25c + Python3 + `lief` + Node.js/npm + `build-essential lib32stdc++-9-dev libc6-dev-i386`；配置代理加速下载。
2. **拉取源码**：`git clone --recurse-submodules -b 16.2.1 https://github.com/frida/frida.git`。
3. **构建 SDK/agent**：`make -f Makefile.sdk.mk ARCH=arm64 -j5`；`make core-android-arm64 FRIDA_HOST=android-arm64`。若链接报 `uncompress`/`inflateInit_`/`crc32`/`deflate` 等 zlib 符号未定义，清理后重编 SDK。
4. **改源码特征**：
   - `gum/gum.c`：`g_set_prgname("frida")` → 自定义名。
   - `gum/backend-darwin/mapper.c` 与 `frida-core/.../agent-container.vala`：`frida_agent_main` → `main`。
   - `frida-core/.../frida-helper-backend.vala`：`memfd_create` 名称 → `jit-cache` 等通用名。
   - `frida-core/.../server.vala`：`DEFAULT_DIRECTORY = "re.frida.server"` → 自定义目录。
   - `frida-core/.../rpc.vala`：`frida:rpc` 改为双重 Base64/数组拼接/运行时解码，避免固定字符串。
5. **改 ELF/字符串/线程名**：用 `topatch.py` 遍历 ELF 符号表，把含 `frida`/`FRIDA` 的符号替换为随机名；在 `.rodata` 搜索 `FridaScriptEngine`、`GLib-GIO`、`GDBusProxy`、`GumScript` 并反转/替换；用 `sed -b` 把 `gum-js-loop`、`gmain`、`gdbus` 改成随机线程名。
6. **接入构建**：确认 `embed-agent.sh.patch` 调用 `topatch.py` 的路径正确；`git apply --check` 批量校验 patch；`make core-android-arm64 | grep Patch` 应输出 Patching 日志。
7. **增量编译**：改源码后用 `ninja -C build`；`make clean` 保留 sdk/toolchain 时重编约 10 分钟，删除则超过 1 小时。
8. **部署验证**：把 `build/frida-android-arm64/bin/frida-server` 推到设备，启动后用目标 APP 的检测项验证进程名/符号/线程名/字符串是否已消失。

## PoC

```text
# 关键 patch 示例（示意）
- g_set_prgname ("frida");
+ g_set_prgname ("russell");

- gum_darwin_mapper_resolve (mapper, "frida_agent_main");
+ gum_darwin_mapper_resolve (mapper, "main");

- container.module.symbol ("frida_agent_main", out main_func_symbol);
+ container.module.symbol ("main", out main_func_symbol);

- return Linux.syscall (SysCall.memfd_create, name, flags);
+ return Linux.syscall (SysCall.memfd_create, "jit-cache", flags);

- private const string DEFAULT_DIRECTORY = "re.frida.server";
+ private const string DEFAULT_DIRECTORY = "re.rusda.server";
```

```python
# topatch.py 核心：符号表与 .rodata 字符串替换
for symbol in binary.symbols:
    if symbol.name == "frida_agent_main":
        symbol.name = "main"
    if "frida" in symbol.name:
        symbol.name = symbol.name.replace("frida", "rusda")
    if "FRIDA" in symbol.name:
        symbol.name = symbol.name.replace("FRIDA", "RUSDA")

for section in binary.sections:
    if section.name != ".rodata":
        continue
    for s in ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]:
        for addr in section.search_all(s):
            binary.patch_address(section.file_offset + addr, [ord(c) for c in s[::-1]])
```

```bash
# 构建与验证
make -f Makefile.sdk.mk ARCH=arm64 -j5
make core-android-arm64 FRIDA_HOST=android-arm64 | grep Patch
# 增量编译
ninja -C build
```

## 变体与关联

- 变体：把 RPC 字符串改成运行时数组拼接/多层 Base64/加密常量，避免双重 Base64 的固定特征。
- 变体：随机化进程名/线程名/目录名，按目标 APP 的检测规则定制。
- 变体：用 IDA-MCP/AI 分析目标 APP 的检测点，针对性修改 Frida 源码。
- 关联：[[mobile-android-anti-detection-root-emulator-proxy]]（Shamiko/HideMyApplist/PlayIntegrityFork 环境隐藏）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（Frida 证书绑定绕过）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（Frida 脱壳）。

## 检测与防御

- 检测：扫描 `/proc/self/maps`/ELF 符号/`.rodata` 中的 Frida 字符串、线程名、`memfd` 名称、`re.frida.server` 目录、`frida:rpc` 协议串。
- 检测：监控 `memfd_create`、匿名可执行内存、ptrace/注入行为；对进程名/线程名做行为关联而非只做字符串匹配。
- 防御：使用 RASP/完整性校验/反调试；检测 Frida 的通信协议与内存特征；不要只依赖固定字符串签名。
- 响应：确认 Frida 注入后，阻断调试端口/进程，审计设备环境，必要时使用硬件级 attestation。
