---
id: ctf-pwn-awdp-format-string-patch
title: AWDP fix：格式化字符串漏洞的二进制级补丁（IDA/KeyPatch 改 printf 调用）
type: scenario
domain: ctf
path: ctf/pwn
technique: awdp-format-string-binary-patch
tags:
- ctf
- pwn
- awdp
- format-string
- binary-patching
- ida
- keypatch
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:50:08+08:00'
  notes: 已对照原文与图01-03核对：printf(format) 调用点、IDA Assemble/KeyPatch 补丁对话框与 0x15CB 机器码一致；原文只说“改汇编”，未明确展示替换成 puts，卡内为通用可落地方案；未复跑
url: /docs/ctf/pwn/ctf-pwn-awdp-format-string-patch/
draft: false
kb_aliases:
- AWDP 格式化字符串修复
- printf(format) 补丁
- IDA Assemble 修改汇编
- KeyPatch 打补丁
- CTF 二进制修复
---

## 一句话结论

AWDP 的 fix 环节遇到 `printf(user_input)` 这类格式化字符串漏洞时，不需要源码：在 IDA 中用 Assemble/KeyPatch 把该 `call printf` 改成不解析格式串的调用（如 `call puts`），或改成固定格式串的 `printf`，直接改写文件中的机器码即可堵住漏洞。

## 原理

- 漏洞形态：`format = readline(); printf(format);`。用户输入被直接当作格式串，`%p`/`%s`/`%n` 可读写栈和任意地址，导致信息泄露乃至任意写。
- 补丁目标：让用户输入不再被解释为格式串。两种等价思路：
  - 把 `printf(format)` 改成 `puts(format)`——`puts` 只输出字符串，不解析 `%`，且 rdi 已经指向 format，一条指令替换即可；
  - 改成 `printf("%s", format)`——需要额外的固定格式串地址与第二个参数，指令空间可能不够，通常需要跳转到代码洞/新增节。
- IDA 的 “Assemble”/“KeyPatch” 直接修改指令并同步修改文件中的真实字节，不需要重新编译；这是 AWDP 只能提交二进制补丁时的核心手段。
- 补丁后要保持调用约定与栈平衡：`puts`/`printf` 都是 cdecl 可变参，调用方不需要额外清栈；若替换为其他函数，要检查 rdi/rsi 参数与返回值是否被后续代码使用。
- 注意：仅修改 `printf` 调用可能影响后续 `puts`/`printf` 的输出格式，但安全优先；补丁后要回归测试功能路径（正常输入、含 `%` 输入、空输入）。

## 触发条件

- AWDP/CTF 修复环节，只能提交二进制补丁（update.tar 内的可执行文件）；
- 目标程序中存在 `printf(user_input)` 或 `fprintf(stream, user_input)` 等格式化字符串漏洞；
- 有 IDA（含 KeyPatch 插件）或等效的十六进制/汇编补丁工具；
- 目标架构与指令长度允许原地替换（x86-64 下 `call rel32` 为 5 字节，换成另一个 `call rel32` 长度相同）。

## 利用步骤

1. 在 IDA 中定位漏洞调用：从 `readline` 的返回值追踪到 `printf`，确认 rdi 直接来自用户输入（如 `mov rax,[rbp+format]; mov rdi,rax; call _printf`）。
2. 在反汇编窗口右键该 `call`，选择 “Assemble...” 或 KeyPatch 的 “Patch” 功能。
3. 将 `call _printf` 改为 `call _puts`（若 rdi 就是格式串）；或改为跳转到代码洞执行 `printf("%s", format)`。
4. 确认补丁对话框中的机器码字节已更新（如 `E8 xx xx xx xx` 的目标地址变化），应用补丁。
5. 保存修改后的二进制，按 AWDP 要求放入 `update/` 目录并打包为 `update.tar`。
6. 本地回归：正常输入、包含 `%p/%n` 的输入、超长输入；确认程序不崩溃且不再泄露/写入。
7. 若补丁影响控制流标志位或后续分支，检查 `test/cmp` 结果并按需调整（见关联的 UAF 补丁卡）。

## PoC

```c
/* 漏洞代码形态 */
format = (char *)readline();
printf("your like ");
printf(format);          /* 漏洞点：format 被当作格式串 */
puts("!?\nI like it too!");
```

```asm
; 原始
mov     rax, [rbp+format]
mov     rdi, rax
call    _printf

; 补丁方案 A：改为 puts（rdi 已是字符串指针）
mov     rax, [rbp+format]
mov     rdi, rax
call    _puts

; 补丁方案 B：改为固定格式串（需要额外空间）
lea     rdi, aPercentS      ; "%s"
mov     rsi, [rbp+format]
xor     eax, eax
call    _printf
```

```bash
# AWDP 补丁包结构示例
mkdir -p update
cp patched_binary update/
cat > update/update.sh <<'EOF'
#!/bin/sh
chmod +x patched_binary
mv -f patched_binary /home/ctf/patched_binary
EOF
tar -cf update.tar update
```

## 变体与关联

- `fprintf`/`sprintf`/`snprintf`/`syslog` 等格式化函数同理，把格式串改为固定串或改用非格式化输出。
- 若漏洞点是 `printf(format)` 且后续依赖其返回值，`puts` 返回值语义不同（非负/EOF），需要检查。
- 无法原地替换时，用 `jmp` 跳到代码洞/新增节执行安全逻辑，再跳回（见 UAF 补丁卡的 jmp 方案）。
- 关联卡片：[[ctf-pwn-awdp-uaf-free-patch]]、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]。

## 检测与防御

- 检测：源码审计中搜索 `printf(`/`fprintf(` 且第一个参数不是字面量的调用；二进制中用 IDA 交叉引用定位 `printf` 调用并检查 rdi 来源。
- 防御：开发时使用固定格式串 `printf("%s", buf)`；开启 `-Wformat-security`/`-Wformat-nonliteral`；对格式化字符串漏洞做输入过滤不能替代正确用法。
- AWDP 场景：补丁要覆盖真实攻击路径，不能只改一处；同一函数可能有多个 `printf` 调用点。
