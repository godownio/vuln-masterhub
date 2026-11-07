---
id: defense-forensics-carriage-return-output-overwrite
title: 用回车符 \r 覆写终端同一行，伪造下载地址、校验结果与进程名
type: scenario
domain: defense
path: defense/forensics
technique: carriage-return-terminal-overwrite
aliases:
- 回车覆写
- CR overwrite
- \r 覆盖终端输出
- 伪造下载地址
- 伪造哈希校验
- 进程名伪装
tags:
- forensics
- log
- terminal
- carriage-return
- spoofing
- checksum
- process-hiding
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:36:12+08:00'
  notes: 已对照原文与图10/11核对：脚本运行后终端只显示伪造的 archive.ubuntu.com 下载地址、sha256 OK 与 [kworker/0:1]，图11 展示被覆盖前的恶意文本；\r+\e[2K 覆盖有效，HTTP 日志 %0d%1b[2K 入口与原文一致。未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

`\r`（0x0D）让光标回到行首而不换行，后续字符会覆盖同一行的已有内容；攻击者在日志或程序输出中插入 `恶意内容\r\e[2K正常内容`，可让管理员只看到伪造的下载地址、校验通过或无害进程名，而且 `\r` 不是转义序列，`less -R` 之类的 ESC 过滤器不会拦它。

## 原理

- 终端对 `\r` 的处理是“光标移到当前行第 0 列”，不换行；随后打印的字符从行首开始覆盖旧字符。
- `\e[2K` 擦除整行，能保证旧内容完全消失，避免长短不一留下残字；只用 `\r` 也能覆盖，但旧行更长时会残留尾部。
- 网络设备、包管理器、校验工具、`ps` 输出都可能把不可信字符串直接写到 tty；攻击者只需控制其中一段。
- 之所以隐蔽：安全审查常关注 `ESC` 序列并过滤 `\x1b`，而 `\r` 是普通控制字符，不在多数“ANSI 过滤器”的名单里；`less -R` 也只处理部分转义序列。

## 触发条件

- 攻击者能控制程序输出或日志中的一段字符串（HTTP 请求路径、下载 URL、文件名、包元数据、进程命令行）；
- 输出直接进入终端渲染，没有把 `\r` 转义为 `\\r` 或删除；
- 受害者依赖终端显示结果做判断（复制下载链接、核对哈希、查看进程列表）；
- 终端未启用“显示控制字符”模式。

## 利用步骤

1. 在可控字段中写入真实恶意内容，紧跟 `\r`（可选 `\e[2K`），再写伪造的正常内容。
2. 让受害者执行查看/安装/排障命令；终端最终只显示覆盖后的文本。
3. 对 URL 场景，受害者复制并访问的是伪造的合法地址；对校验场景，显示 `OK` 而实际校验失败；对进程场景，`xmrig` 被显示为 `[kworker/0:1]`。

## PoC

```bash
# 1. 下载地址伪装
printf 'Downloading http://evil.example/rootkit.sh\r\e[2KDownloading http://archive.ubuntu.com/release.tar.gz\n'

# 2. 校验结果伪装
printf 'sha256: MISMATCH - file is corrupted!\r\e[2Ksha256: OK - verified successfully\n'

# 3. 进程名伪装
printf ' 5678 pts/0 03:14:15 xmrig --coin=XMR\r\e[2K 5678 pts/0 00:00:01 [kworker/0:1]\n'
```

HTTP 日志入口：请求路径包含 `%0d%1b[2K`，access.log 中该行被覆盖为伪造的合法请求记录。

验证：

```bash
cat -v dirty.log      # 显示 ^M 与 ^[[2K
hexdump -C dirty.log | grep ' 0d '
```

## 变体与关联

- 变体：只用 `\r` 多次覆盖制造“进度条”式刷新；配合 `\b` 退格逐字改写；在 `tail -f` 实时输出中覆盖告警行；在 CI 日志中伪造测试通过。
- 关联：[[defense-forensics-ansi-escape-log-poisoning]]（ESC 清屏/隐藏，属转义序列类）；两者可组合：先清屏再打印伪造日志。
- 影响边界：只欺骗终端显示；原始文件用 `cat -v`/`hexdump` 可见。若输出被重定向到文件再由日志平台解析，覆盖效果取决于解析器是否按行处理 `\r`（部分系统把 `\r` 当行分隔）。

## 检测与防御

- 检测：日志/输出中出现 `0x0d`（非 Windows 换行场景）；`cat -v` 显示 `^M`；同一行在 `\r` 前后内容不一致；下载/校验类输出中 URL 与校验值出现控制字符。
- 防御：展示不可信文本前删除或转义 `\r`、`\b` 及全部 C0 控制字符；封装查看命令（`cat -v`、`less -U`、`hexdump -C`）；自动化校验不要只打印结果，失败时以非零退出码阻断流程；终端启用控制字符可视化。
