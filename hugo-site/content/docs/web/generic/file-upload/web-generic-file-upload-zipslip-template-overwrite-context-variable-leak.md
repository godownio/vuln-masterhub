---
id: web-generic-file-upload-zipslip-template-overwrite-context-variable-leak
title: Zip Slip 覆盖服务端模板泄露隐藏上下文变量：上传压缩包写 memo.html 后 {{flag}} 直接渲染
type: scenario
domain: web
path: web/generic/file-upload
technique: zipslip-template-overwrite-context-variable-leak
tags:
- web
- file-upload
- zip-slip
- path-traversal
- arbitrary-write
- template
- jinja2
- info-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:52:06+08:00'
  notes: 已对照原文「guess」核对：/status 泄露 archive_root=C:/Program Files/Git/app/uploads/themes/<id>、renderer=/app/templates/memo.html、allowed=.txt,.css,.html、required=manifest.txt；ZIP 条目 ../../../templates/memo.html 从 <id> 上跳三级到 /app/templates/，payload 枚举 flag/FLAG/flag_text/secret/config/request.url，访问 /memo 渲染得 flag；PoC 与原文脚本一致。核对中修正 tag：该题在 92784 原文明确为 Jinja2，已将 twig 改为 jinja2（knowledge 与 staging 同步）。未复跑；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-zipslip-template-overwrite-context-variable-leak/
draft: false
kb_aliases:
- Zip Slip 模板覆盖
- 模板变量泄露
- memo.html 覆盖
- 隐藏上下文变量渲染
- 上传解压穿越写模板
---

## 一句话结论

上传功能按压缩包内的相对路径解压且未做规范化，攻击者用 `../` 路径把恶意文件写到应用模板目录、覆盖正在使用的 `memo.html`；模板渲染上下文里本来就存在 `flag` 等隐藏变量，覆盖后的模板写入 `{{ flag }}` 即可在下次渲染时把敏感变量输出到页面，无需 RCE。

## 原理

- **状态接口泄漏布局**：`/status` 返回 `archive_root=/app/uploads/themes/<id>`、`renderer=/app/templates/memo.html`、`allowed=.txt,.css,.html`、`required=manifest.txt`；攻击者由此知道解压根目录、模板文件位置与上传校验规则。
- **Zip Slip**：解压时把条目名直接拼到 `archive_root` 后面，没有做 `realpath`/`commonpath` 校验；条目名 `../../../templates/memo.html` 会从 `/app/uploads/themes/<id>` 上跳三级到 `/app/templates/`，覆盖 `memo.html`。
- **扩展名白名单不等于路径安全**：`.html` 通过扩展名白名单，但目标目录由条目名决定；白名单只限制后缀，不限制写入位置。
- **隐藏上下文变量**：`/memo` 的渲染上下文已注入 `flag`、`FLAG`、`flag_text`、`secret`、`config`、`request` 等变量，但默认模板不输出它们。模板文件可写后，攻击者用 `{{ flag }}` 等表达式即可读取这些变量；这属于模板层的敏感变量泄露，不一定需要命令执行。
- **为什么覆盖模板有效**：模板引擎每次渲染都会读取模板文件（或从缓存重新加载），覆盖后下一次请求 `/memo` 就使用恶意模板；`manifest.txt` 用于满足“必需文件”检查，确保上传流程通过。

## 触发条件

- 上传压缩包后由服务端解压到固定目录，解压路径可由条目名控制（Zip Slip）。
- 解压目标目录与模板目录可通过 `../` 相对路径到达，且解压进程对模板目录有写权限。
- 上传校验只检查扩展名/必需文件，不校验解压后的真实路径。
- 模板渲染上下文包含敏感变量，且模板文件可被覆盖或新增。
- 模板引擎允许直接访问上下文变量（Twig/Jinja2 等 `{{ var }}`）。

## 利用步骤

1. 访问 `/status`（或类似调试/状态接口）获取解压根目录、模板路径、扩展名白名单、必需文件。
2. 计算穿越层级：`archive_root=/app/uploads/themes/<id>` 到 `/app/templates/` 需要 `../../../templates/`。
3. 构造 ZIP：加入 `manifest.txt` 满足必需文件检查；加入 `../../../templates/memo.html`，内容为读取隐藏变量的模板，例如 `flag={{ flag }}`、`FLAG={{ FLAG }}`、`secret={{ secret }}`。
4. 上传 ZIP，服务端解压并覆盖模板。
5. 访问 `/memo` 触发模板渲染，页面输出隐藏变量值；若变量名不确定，可在同一模板中枚举多个候选名。
6. 若模板目录不可写，改为写入其他可被包含/执行的位置（视图缓存、静态目录 + 模板包含链）。

## PoC

```python
import zipfile

payload = '''<pre>
flag={{ flag }}
FLAG={{ FLAG }}
flag_text={{ flag_text }}
secret={{ secret }}
config={{ config }}
request={{ request.url }}
</pre>'''

paths = [
    '../templates/memo.html',
    '../../templates/memo.html',
    '../../../templates/memo.html',   # 命中：/app/uploads/themes/<id> -> /app/templates/
    '../../../../templates/memo.html',
]

with zipfile.ZipFile('slip1.zip', 'w') as z:
    z.writestr('manifest.txt', 'name=x\n')
    for p in paths:
        z.writestr(p, payload)
```

上传后访问 `/memo`，原文成功渲染出 flag；未在本机复跑。

## 变体与关联

- **目标文件变体**：覆盖布局模板、错误页、邮件模板、PDF 模板；若模板可执行表达式，可能进一步升级为 SSTI/RCE。
- **写入位置变体**：视图缓存目录、静态资源目录 + 路径穿越包含、日志文件 + 包含、计划任务/配置目录。
- **绕过变体**：绝对路径条目、`..%2f` 编码、符号链接条目、大小写/分隔符差异（Windows `..\`）。
- **关联**：[[web-generic-file-upload-zip-slip-webshell-write]]（Zip Slip 写 WebShell）、[[web-generic-file-upload-jeewms-cgformtemplate-zipslip-templatecode]]（模板目录穿越）；本卡的区别是目标为“覆盖模板读取隐藏变量”，不依赖 RCE。

## 检测与防御

- 解压前对每个条目做规范化：`realpath(join(dest, name))` 必须以 `dest` 为前缀，拒绝绝对路径、`..`、符号链接与空字节。
- 上传目录与模板目录分离，解压进程对模板目录只读；模板文件使用不可变/签名机制。
- 扩展名白名单之外，增加内容与路径双重校验；必需文件检查不能替代路径校验。
- 模板渲染上下文最小化：不要把 `flag`、密钥、配置对象等敏感变量注入所有模板；使用显式变量白名单。
- 检测：ZIP 条目含 `../`、解压后模板文件 mtime/哈希变化、`/memo` 等页面出现异常变量输出、上传目录与模板目录之间出现跨目录写入。
