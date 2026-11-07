---
id: web-python-flask-config-object-pollution-filename-file-read
title: Flask config 对象污染：merge 写入 config.filename 导致任意文件读取
type: scenario
domain: web
path: web/python
technique: flask-config-object-pollution-filename-file-read
aliases:
- Flask config 污染
- config.filename
- instance.config
- Python 配置对象污染
- 任意文件读取
tags:
- python
- flask
- config-pollution
- merge
- file-read
- arbitrary-file-read
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:11:27+08:00'
  notes: 已对照原文核对：/read 路由 open(instance.config.filename).read()、payload {"config":{"filename":"/flag"}} 与原文一致。核对时修正了卡片中 merge 目标表述：若直接 merge 进 config 本身应提交 {"filename":"/flag"}，原文 payload 对应的是 merge 进持有 config 的对象（instance/app）；已同步修改 staging 与 knowledge 文件。未验证点：原文未给出 merge 入口代码，属推断；PoC 未运行；原文未给版本；frontmatter 无 sources/source_url。
---

## 一句话结论

应用把用户 JSON 递归 merge 进持有 Flask `instance.config` 的对象后，若某个路由直接 `open(instance.config.filename).read()`，提交 `{"config":{"filename":"/flag"}}` 即可把 `config.filename` 改成任意路径，访问该路由读取 flag 或任意文件。

## 原理

- **Flask Config 是可变映射**：`app.config`/`instance.config` 本质是 dict-like 对象，支持 `config["KEY"]=value` 与属性式访问；递归 merge 会把用户 JSON 的键写入该对象。
- **filename 是普通键**：Flask 本身没有 `config.filename` 这个标准配置，但 Config 对象允许任意键；应用若把“备份/模板/数据文件路径”存在 `config.filename`，用户就能通过 merge 覆盖它。
- **sink 直接 open**：`/read` 路由执行 `open(instance.config.filename).read()`，没有白名单/realpath 校验；覆盖成 `/flag` 后即可读任意文件。
- **为什么 merge 能到 config**：若入口把用户 JSON 递归 merge 进一个持有 `config` 属性的对象（如 `instance`/`app`），`data` 的 `config` 键会递归进入该对象的 `config`，最终把 `filename` 写成用户值；若入口直接 merge 进 config 本身，则 payload 应为 `{"filename":"/flag"}`。即使 merge 过滤了 `__proto__`，Python 侧仍可能允许 `config`/`filename` 这类普通键。
- **与类污染的区别**：这不是 `__class__.__globals__` 提权，而是把用户数据写进一个被业务信任的配置对象；危害取决于哪些代码读取该配置。

## 触发条件

- 应用存在把用户可控 JSON 递归 merge 进 `app.config`/`instance.config`/自定义 config 对象的入口。
- 代码中存在 `config.<attr>` 或 `config["attr"]` 被用于文件路径、模板路径、上传目录等 sink。
- 没有对配置键做白名单，也没有对最终路径做 realpath/前缀校验。
- 目标文件对进程可读（如 `/flag`、`/etc/passwd`、源码）。

## 利用步骤

1. 找到 merge 入口与目标 config 对象；确认普通键（如 `config`、`filename`）能被写入。
2. 提交 `{"config":{"filename":"/flag"}}`（或按实际层级调整，如 `{"filename":"/flag"}`）。
3. 访问读取配置的路由（如 `/read`），获取文件内容。
4. 若被过滤，尝试嵌套键、大小写、Unicode 转义或 `config["filename"]` 形式；Python dict 的键匹配通常区分大小写。
5. 读取源码/配置/凭据后继续扩大影响；若可写路径，可进一步写文件/模板。

## PoC

```python
# 脆弱路由
@app.route('/read')
def read():
    return open(instance.config.filename).read()
```

```http
POST /api/config HTTP/1.1
Content-Type: application/json

{"config":{"filename":"/flag"}}
```

```http
GET /read HTTP/1.1
Host: target
```

## 变体与关联

- **配置键变体**：`config.filename`、`config['filename']`、`config.data_path`、`config.template_folder`、`config.upload_dir`；找到读取点即可。
- **污染路径变体**：直接 merge 到 config、merge 到包含 config 的对象、通过 `__class__.__init__.__globals__` 改模块级 config；见关联卡片。
- **sink 变体**：`open()`、`send_file()`、`render_template()`、`os.listdir()`、`subprocess` 参数；危害从文件读取到 RCE。
- **关联卡片**：[[web-python-recursive-merge-class-pollution-globals-rce]]（Python 递归合并类污染）、[[web-generic-file-inclusion-flask-sendfile-download-traversal]]（Flask 下载穿越）、[[web-python-framework-flask-static-folder-arbitrary-file-read]]（static_folder 改写读文件）。
- **边界**：merge 只接受白名单键、config 被冻结/只读、sink 使用固定路径或 realpath 校验时失效。

## 检测与防御

- **检测特征**：请求体含 `config`/`filename`/`path` 等键；配置对象在请求后出现异常键；文件读取路由被传入绝对路径。
- **修复**：不要把用户输入 merge 进 config；使用显式字段白名单与类型校验；文件路径用 `realpath` + `commonpath` 限制在允许目录；配置对象只读/冻结。
- **最小权限**：Web 进程以低权限运行，flag/源码/配置不可读；敏感文件放到进程不可达的目录。
