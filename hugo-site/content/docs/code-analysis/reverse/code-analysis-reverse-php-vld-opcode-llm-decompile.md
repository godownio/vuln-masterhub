---
id: code-analysis-reverse-php-vld-opcode-llm-decompile
title: PHP 字节码反编译：VLD 导出 OPCode 后交给 LLM 还原源码结构
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: php-vld-opcode-llm-decompile
tags:
- php
- vld
- opcode
- decompile
- llm
- gpt
- reverse
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V435
  verified_at: '2026-11-09T20:28:37+08:00'
  notes: 已对照原文与图29（6.1 PHP反编译器）核对：左侧混淆 PHP 源码经 VLD 输出 OPCode（filename/function name/number of ops 52/compiled vars !0=$G_LIB,!1=$G_MAILLIB,!2=$session；RECV/BIND_GLOBAL/NEW mailbox_mails/DO_FCALL/ASSIGN_DIM $G_LIB,'mailbox'/OP_DATA/INIT_METHOD_CALL 'set_userid'/FETCH_DIM_FUNC_ARG $session,'id'/SEND_VAR_EX/DO_FCALL/FETCH_DIM_R $G_LIB,'maildir'），右侧 GPT 反编译输出 $G_LIB['mailbox']=new mailbox_mails()、set_userid/set_maildir/set_mailbox 等 PHP 代码，卡内流程与示例一致。核对中已按图修正卡内原理示例：原文误写 FETCH_DIM_R $GLOBALS['session']/SEND_VAL，改为 BIND_GLOBAL $session+FETCH_DIM_FUNC_ARG $session,'id'+SEND_VAR_EX，并注明 FETCH_DIM_R $G_LIB,'maildir' 为读全局数组元素。VLD 命令 vld.active=1/vld.execute=0 为原文未展开的标准用法（卡内已注明按版本确认），未实测。原文未给组件版本，affected_versions 留空正确；dedup 首位为自身 exact 自比对，其余为自定义 VM/字节码逆向卡（new），不同链。dup-scan.json 早于建卡且无本篇 pair。
url: /docs/code-analysis/reverse/code-analysis-reverse-php-vld-opcode-llm-decompile/
draft: false
kb_aliases:
- PHP 反编译器
- VLD OPCode
- PHP 字节码还原
- LLM 反编译 PHP
- PHP 源码重建
- vld.active
---

## 一句话结论

PHP 没有像 dnSpy 那样成熟的源码级反编译器，但可以用 VLD 扩展在执行时导出 OPCode 列表（操作码、操作数、函数/类调用），再把这份字节码清单交给长上下文 LLM，让它按“函数调用、对象创建、全局变量访问、控制流”的模式还原出等价的 PHP 源码结构，作为人工逆向的起点。

## 原理

- PHP 先编译为 OPCode 再执行；VLD（Vulcan Logic Dumper）是常用扩展，开启后会把每个函数/文件的 OPCode 逐条打印出来，包含 opcode 名称（如 RECV、INIT_METHOD_CALL、DO_FCALL、ASSIGN_DIM、FETCH_DIM_R、NEW、SEND_VAL 等）、操作数、返回操作数与行号。
- OPCode 保留了控制流与调用关系，但会丢失部分源码层级信息（局部变量名可能只剩 CV 槽位、表达式被拆成多条指令、常量折叠/优化可能改变结构）；直接读 OPCode 反推源码需要经验。
- LLM 擅长把“指令序列 → 高层语义”的模式匹配：例如 `NEW mailbox_mails` + `DO_FCALL` + `ASSIGN_DIM $G_LIB,'mailbox'` + `OP_DATA` 可还原为 `$GLOBALS['__LIB']['mailbox'] = new mailbox_mails();`；`INIT_METHOD_CALL $3,'set_userid'` + `FETCH_DIM_FUNC_ARG $session,'id'` + `SEND_VAR_EX` + `DO_FCALL` 可还原为对象方法调用；`BIND_GLOBAL $session` + `FETCH_DIM_FUNC_ARG $session,'id'` 对应 `global $session;` 与 `$session->id`，`FETCH_DIM_R $G_LIB,'maildir'` 为读全局数组元素。
- 幻灯片展示的流程：PHP 源码 → VLD 逆向获取 OPCode → GPT 实现反编译器，输出带有 `$GLOBALS`、`new mailbox_mails`、`set_userid`、`set_mailbox` 等调用的 PHP 代码。LLM 的输出是“语义等价近似”，适合快速理解业务逻辑与敏感数据流，而不是逐字节精确还原。
- 价值：面对加密/混淆/无源码的 PHP 应用（或只有 opcache/字节码的场景），先用 VLD 拿到可读指令，再让模型批量翻译，能显著降低人工阅读成本；结果可用于定位后门、危险函数与数据流。

## 触发条件

- 能运行目标 PHP 代码并安装/启用 VLD 扩展（或能获得 OPCode 转储）。
- PHP 版本与 VLD 兼容；代码不是纯 `eval`/动态生成导致 OPCode 不可得。
- 有能处理较长指令序列的 LLM（本地或 API），并允许把代码片段送给它（注意保密）。

## 利用步骤

1. 安装 VLD 扩展，确认 `php -m` 可见；用 `php -d vld.active=1 -d vld.execute=0 <script>.php` 输出 OPCode（`vld.execute=0` 避免真正执行不受信任代码，按版本确认参数行为）。
2. 保存目标函数/文件的 OPCode 段落，必要时按函数拆分，避免超出模型上下文。
3. 给 LLM 的提示：说明这是 PHP VLD OPCode，要求按 opcode 语义还原为可读 PHP（保留函数/类名与全局变量，控制流用 if/foreach/return 表示，不确定处标注）。
4. 对照行号与调用关系人工校验；对关键数据流（输入→数据库/文件/命令）单独追问。
5. 将还原结果用于后续审计（危险函数、反序列化、SQL 拼接等），必要时用运行时 hook/动态调试验证。

## PoC

无完整 PoC（原文为幻灯片中的流程演示）。核心命令与提示骨架：

```bash
# 1) 用 VLD 导出 OPCode（不执行）
php -d vld.active=1 -d vld.execute=0 target.php > opcode.txt
```

```text
下面是一个 PHP 文件的 VLD OPCode 列表（opcode + operands + line）。
请将它还原为语义等价的 PHP 源码：
- NEW/DO_FCALL/INIT_METHOD_CALL 还原为对象创建与方法调用；
- ASSIGN_DIM/FETCH_DIM_R 还原为数组/全局变量读写；
- 保留函数名、类名、全局变量名；不确定处用注释标注。
```

## 变体与关联

- 变体：phpdbg/opcache 的 opcode dump；Xdebug 跟踪调用序列；对 Python `dis`、JVM/IL 字节码、Lua 字节码做同样的“字节码 + LLM 翻译”。
- 关联 [[code-analysis-reverse-obfuscation-php-gzinflate-strtr-base64-unwrap]]：PHP 混淆壳的静态还原；本卡针对已编译 OPCode 的语义反编译，二者可串联（先脱壳再反编译）。
- 关联 [[code-analysis-reverse-windows-dotnet-metadata-token-rva-method-body]]：同为字节码/IL 级定位，但语言与工具链不同。
- 边界：OPCode 优化会丢失源码结构；局部变量名/注释不可恢复；动态特性（`eval`、可变函数、include 路径）使静态还原失真；LLM 可能编造不存在的逻辑，必须人工验证。

## 检测与防御

- 防御（PHP 应用保护）：使用 opcache/源码加密/商业混淆提高逆向成本；但运行期仍需解密，无法阻止 VLD 式转储，重点应放在减少前端源码与密钥暴露。
- 检测：生产环境不应安装 VLD/Xdebug 等调试扩展；监控异常的 `php -d vld.active=1` 进程与 opcode 转储文件。
- 分析侧：把 LLM 输出当作“可读草稿”，用运行时日志/断点验证关键分支，避免被幻觉误导。
