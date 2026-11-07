---
id: ctf-forensics-pdf-annotation-redirect-phishing-url-extraction
title: 批量 PDF 钓鱼链接提取：Annotation URI + 正文 URL + redirect 参数域名白名单与 MD5
type: scenario
domain: ctf
path: ctf/forensics
technique: pdf-annotation-redirect-phishing-url-extraction
aliases:
- PDF 钓鱼链接分析
- PyMuPDF get_links
- Annotation URI 提取
- redirect/next 参数跳转
- 域名白名单过滤
- 批量 PDF URL 审计
tags:
- ctf
- forensics
- pdf
- phishing
- url
- annotation
- pymupdf
- domain-filter
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:05:51+08:00'
  notes: 已对照 91111 原文数据分析第三题核对：veritytech.com 白名单、Annotation URI、redirect/next/url 参数、排序拼接 MD5 0a16f1ca5e8db1270074d0d39f6edeaf 均一致；卡片已注明正文 URL 提取为补充项。PoC 未在本机复跑。
---

## 一句话结论

批量审计 PDF 时，不能只看正文文本：钓鱼 URL 可能藏在 Annotation 的 `/URI` 动作里，也可能藏在合法域名 URL 的 `redirect`、`next`、`url` 等参数值中。用 PyMuPDF 遍历每页的 `get_links()` 与正文，提取所有 http(s) URL，先按 `veritytech.com` 及其子域名白名单判断主域名，再单独解析跳转参数并对参数值做同样判断；把所有非白名单 URL 去重、字典序排序、逗号拼接后计算 MD5。

## 原理

- **PDF 链接的三种载体**：
  1. 正文可见文本中的 URL（需 `page.get_text()` + 正则）；
  2. Annotation 的链接动作（`page.get_links()` 返回 `{'kind': LINK_URI, 'uri': '...'}`），显示文字与真实 URI 可以不同；
  3. URL 查询参数中的跳转地址（如 `https://mail.veritytech.com/auth?next=https://evil.com/login`），完整 URL 的主域名合法，但参数值指向外部。
- **白名单判断**：`domain == 'veritytech.com' or domain.endswith('.veritytech.com')`；注意 `veritytech.com.io`、`verify-veritytech.xyz`、`compaпy.com`（西里尔字母 homoglyph）都不满足，应判为外部。
- **URL 清洗**：PDF 文本/Annotation 常带尾部标点（`）`、`，`、`。`、`;`、`)`、`]`），需在解析前剥离，否则域名/参数解析会失败。
- **跳转参数**：常见 key 包括 `redirect`、`next`、`url`、`return`、`return_url`、`goto`、`target`、`link`、`dest`、`destination`、`redir`、`redirect_uri`、`redirect_url`；参数值需 `unquote` 后再判断是否 http(s)。
- **去重与排序**：同一 URL 可能在多份 PDF/多个页面出现；用 set 去重，`sorted()` 字典序排序，`','.join()` 拼接后 MD5，保证结果稳定可复现。
- **为什么可复用**：钓鱼 PDF 常把恶意链接藏在 Annotation/重定向参数中，纯文本扫描会漏；本流程适用于邮件附件、文档服务器、批量取证。

## 触发条件

- 有一批 PDF（可正常打开/已解密），需要找出所有外部/钓鱼链接。
- 已知合法域名/子域名白名单，以及需要检查的跳转参数名。
- PDF 中包含 Annotation URI、正文 URL 或带跳转参数的合法域名 URL。
- 有 PyMuPDF/`fitz` 或同类 PDF 解析库。

## 利用步骤

1. 建立合法域名判断函数：等于主域或以 `.主域` 结尾；排除 `.local`、`.internal`、无点内部主机名。
2. 遍历 PDF：用 `page.get_links()` 取 Annotation URI；用 `page.get_text()` + URL 正则取正文 URL。
3. 对每个 URL 做清洗（去尾部标点/空白），解析 `urlparse` 的 scheme/netloc；只保留 http/https 且域名带点的 ASCII URL。
4. 若完整 URL 的主域名不在白名单，加入结果集；再解析查询参数中的跳转 key，`unquote` 后对参数值重复第 3-4 步，外部则加入结果集。
5. 去重、字典序排序、逗号拼接；计算 MD5（或按题目要求输出列表）。
6. 人工复核命中项：检查 homoglyph、短链、`@` 用户信息、端口/IP、IDN/punycode；必要时用浏览器/威胁情报确认。
7. 若结果与预期不符，检查是否漏了正文提取、Annotation 类型、参数大小写、URL 编码层级（双重编码）。

## PoC

```python
import hashlib, glob, re
import fitz  # PyMuPDF
from urllib.parse import urlparse, parse_qs, unquote

ALLOWED = 'veritytech.com'
REDIRECT_KEYS = {
    'redirect', 'next', 'url', 'return', 'returnurl', 'return_url',
    'goto', 'target', 'link', 'dest', 'destination', 'redir',
    'redirect_uri', 'redirect_url',
}
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)

def domain_of(url):
    try:
        netloc = urlparse(url).netloc
        return netloc.split(':')[0].lower()
    except Exception:
        return ''

def allowed(domain):
    return domain == ALLOWED or domain.endswith('.' + ALLOWED)

def internal(domain):
    return (not domain) or domain.endswith('.local') or domain.endswith('.internal') or '.' not in domain

def clean(url):
    url = url.strip()
    url = re.sub(r'[）），。；\s].*$', '', url)
    return url.rstrip('.,;:!?）)>]')

def valid(url):
    if not url.startswith(('http://', 'https://')):
        return False
    d = domain_of(url)
    return bool(d) and '.' in d and all(ord(c) < 128 for c in url)

def redirect_values(url):
    out = []
    try:
        for k, vals in parse_qs(urlparse(url).query).items():
            if k.lower() in REDIRECT_KEYS:
                for v in vals:
                    v = unquote(v)
                    if v.startswith(('http://', 'https://')):
                        out.append(v)
    except Exception:
        pass
    return out

hits = set()
for pdf in glob.glob('decrypted_pdfs/*.pdf'):
    try:
        doc = fitz.open(pdf)
    except Exception:
        continue
    for page in doc:
        urls = []
        for link in page.get_links():
            if 'uri' in link:
                urls.append(link['uri'])
        urls += URL_RE.findall(page.get_text())
        for raw in urls:
            u = clean(raw)
            if not valid(u):
                continue
            if not allowed(domain_of(u)) and not internal(domain_of(u)):
                hits.add(u)
            for r in redirect_values(u):
                r = clean(r)
                if valid(r) and not allowed(domain_of(r)) and not internal(domain_of(r)):
                    hits.add(r)
    doc.close()

ordered = sorted(hits)
print('\n'.join(ordered))
print(hashlib.md5(','.join(ordered).encode()).hexdigest())
```

说明：原文答案为 `0a16f1ca5e8db1270074d0d39f6edeaf`；原文脚本主要走 Annotation URI，本卡补充了正文 URL 与更完整的跳转参数处理。PoC 未在本机复跑。

## 变体与关联

- **载体变体**：PDF Annotation `/URI`、`/Launch`、`/SubmitForm`、JavaScript `app.launchURL`、嵌入文件/附件、表单字段、书签；正文文本/OCR 结果。
- **混淆变体**：URL 编码/双重编码、HTML 实体、大小写、短链、`@` 用户信息、IP/端口、IDN/punycode、homoglyph、零宽字符、换行拆分。
- **白名单变体**：精确域、后缀匹配要防止 `evil-veritytech.com`/`veritytech.com.evil.com`；用 PSL（Public Suffix List）解析可注册域更稳。
- **关联卡片**：[[ctf-forensics-docm-vba-base64-xor-powershell-download-url]]（文档宏下载 URL）、[[ctf-forensics-docx-customxml-base64-comment]]（文档隐藏数据）、[[web-generic-open-redirect]]（跳转参数滥用）。
- **边界**：加密/损坏 PDF 无法解析；扫描件需 OCR；仅提取 URL 不代表恶意，需结合域名信誉/内容判定。

## 检测与防御

- **检测（防守方）**：邮件/文档网关对 PDF Annotation URI 与正文 URL 做提取与信誉检查；监控指向非白名单域的跳转参数；对批量文档做一致性审计。
- **防御**：PDF 阅读器禁用自动打开 URI/启动程序；企业配置 URL 白名单/代理；对下载文档做沙箱打开与静态分析。
- **取证**：保留原始 PDF 与哈希；记录提取来源（正文/Annotation/参数）、页面与对象编号；对命中 URL 做截图/离线保存，避免访问。
- **合规**：批量提取可能涉及员工/客户文档，需授权与最小化，结果按敏感数据管理。
