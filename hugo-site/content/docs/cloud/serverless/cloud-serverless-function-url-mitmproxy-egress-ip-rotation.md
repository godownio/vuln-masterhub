---
id: cloud-serverless-function-url-mitmproxy-egress-ip-rotation
title: 用云函数当出口 IP 池：mitmproxy 插件把整条流量改写成 POST 到函数 URL，靠云厂商 NAT 出口绕过 IP 封禁与限速
type: scenario
domain: cloud
path: cloud/serverless
technique: serverless-function-url-egress-ip-rotation-proxy
tags:
- serverless
- scf
- proxy
- mitmproxy
- ip-rotation
- anti-blocking
- python
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:36:02+08:00'
  notes: 已对照原文核对：服务端 main_handler 的 scf-token 校验/401、json.loads(event['body'])、b64decode(data)、requests.request(**kwargs, verify=False, allow_redirects=False)、pickle.dumps+b64encode 回传；客户端 client.py 的 request/response 两个 hook、flow.request.make 改写为 POST、401/433 分支、scf_servers 随机 choice、mitmdump -s client.py -p 9999 --no-http2，均与正文代码块一字对应；『每次请求源 IP 不同且归属云厂商』正文有文字描述（VPS http.server 对比）。本次核对未读取图片；截图中的控制台配置/代理插件截图/IP 归属查询结果未核对。dedup：t2_card 判 duplicate 但 top 为草稿自身（1.000），排除后最高外部候选 pentest-c2-webshell-loadbalancer-mitmproxy-404-retry 0.100、tools-burp 双代理链 0.080、mtls-mitm 0.079 均为不同链，与 pentest-c2-faas-flask-proxy-traffic-forwarding 的差异（redirector 隐藏基础设施 vs 出网 IP 池）成立；skipped 的 pickle 反序列化未成卡理由（原文无攻击者视角 PoC）合理
url: /docs/cloud/serverless/cloud-serverless-function-url-mitmproxy-egress-ip-rotation/
draft: false
kb_aliases:
- 云函数代理池
- SCF 代理
- 函数 URL 代理
- 云函数绕 IP 封禁
- serverless 出口 IP 轮换
- mitmproxy 云函数分发
---

## 一句话结论

把「转发请求」这件事从自建代理换成云函数：服务端函数用 `requests.request(**kwargs)` 原样重放收到的 method/url/headers/params/body，客户端写一个 mitmproxy 插件把每个 flow 的请求体序列化成 JSON、改成 `POST <函数 URL>`、并把真实响应从函数返回体里还原回 flow，于是每个请求都从云厂商的 NAT 出口池出网——源 IP 每次不同且归属云厂商，天然绕过按源 IP 的封禁与频率限制。

## 原理

- **出口 IP 来自云侧而非自己**：函数计算实例的网络出口由平台统一 NAT，同一函数的多次调用可能落在不同实例/不同 NAT 出口上，所以对端看到的是云厂商的地址池而不是固定 IP。原文用自建 VPS 起 `http.server` 观察：不走代理时每次都是同一 IP，走云函数后每次请求的源 IP 都变，且查询归属为部署云函数的服务商与地域。
- **为什么必须用 mitmproxy 而不是普通 HTTP 代理**：云函数 URL 只接受它自己的 HTTP 调用，客户端无法把 `CONNECT`/绝对 URI 直接交给它。mitmproxy 插件在本地接管 flow（含 HTTPS，需安装 mitmproxy CA 到客户端信任区），在 `request(flow)` 里把原始请求的 `method/url/headers/cookies/query/raw_content` 打包成 JSON（body 用 base64），再把 flow 改写为指向函数 URL 的 POST；这层转换让"任意目标站点"都能经同一入口转发。
- **为什么响应要序列化回传**：函数侧拿到的 `requests.Response` 无法直接作为 body 返回，用 `pickle.dumps(r)` + base64 把它整体序列化回来，客户端在 `response(flow)` 里 `pickle.loads` 还原出 `status_code/headers/content`，重建成 `flow.response`，浏览器侧无感。
- **鉴权是自建代理的必需项**：函数 URL 是公网可调用的，如果不校验自定义头（原文用 `SCF-Token`），任何人拿到地址都能把它当免费开放代理用。原文在 `main_handler` 里先从 `event["headers"]` 取 `scf-token`，不匹配即返回 401。
- **为什么能扛住封禁**：封禁方通常按源 IP 做黑/白名单或限速；出口 IP 分散到云厂商地址池后，单个 IP 的请求量被稀释，触发阈值的概率大幅下降；同时被访问方看到的是云服务商地址，白名单策略里往往本就允许。

## 触发条件

- 能注册云函数平台并创建函数 URL（原文用腾讯云 SCF，Python 3.6 运行环境，事件函数），平台允许函数内 `requests` 发起任意出站 HTTP(S)。
- 客户端能运行 mitmproxy 并在目标应用/浏览器中信任其 CA（要代理 HTTPS 流量必须）。
- 代理链路只解决"谁出网"，不解决目标侧的账号级风控、验证码、WAF payload 检测——这些仍需另行处理。
- 平台的计费与配额允许该请求量（按调用次数与执行时长计费，原文提到新用户有试用额度）。

## 利用步骤

1. 在云函数控制台新建事件函数（运行环境 Python 3.x），把服务端代码写入在线编辑器：读取 `event["headers"]["scf-token"]` 校验 → `json.loads(event["body"])` → base64 解码 body → `requests.request(**kwargs, verify=False, allow_redirects=False)` → `pickle.dumps(r)` 后 base64 放回响应体。
2. 创建函数 URL（触发器中的 API 网关类型下线后直接用函数 URL），拿到 `https://<id>-<name>.<region>.tencentscf.com` 形式的入口。
3. 本地 `pip3 install mitmproxy`，首次运行 `mitmdump` 生成 `~/.mitmproxy` 下的 CA，双击安装到系统/浏览器信任区。
4. 写 `client.py`：`request(flow)` 里把 flow 改写成对函数 URL 的 POST（headers 带 `SCF-Token`）；`response(flow)` 里对 200 响应做 base64 解码 + `pickle.loads`，用还原出的状态码/头/内容重建 `flow.response`，并对 401（鉴权失败）、433（执行超时）单独处理。
5. 把函数 URL 填进 `scf_servers` 列表（可放多个域名/地域做轮换），`SCF_TOKEN` 与服务端保持一致。
6. 启动 `mitmdump -s client.py -p 9999 --no-http2`，把目标应用的代理指向 `127.0.0.1:9999`。
7. 验证出口 IP 已轮换：用被控端访问一个回显源 IP 的自建服务，连续多次观察源 IP 是否变化、归属是否为云厂商。

## PoC

```python
# 服务端：云函数事件函数（函数 URL 入口）
def main_handler(event, context):
    try:
        token = event["headers"]["scf-token"]
    except KeyError:
        return {"statusCode": 401, "body": "Please provide correct SCF-Token"}
    if token != SCF_TOKEN:
        return {"statusCode": 401, "body": "Please provide correct SCF-Token"}

    kwargs = json.loads(event["body"])
    kwargs["data"] = b64decode(kwargs["data"])
    r = requests.request(**kwargs, verify=False, allow_redirects=False)
    return {"statusCode": 200, "body": b64encode(pickle.dumps(r)).decode("utf-8")}
```

```python
# 客户端：mitmproxy addon，必须命名为 client.py 才能被 -s 直接加载
def request(flow):
    r = flow.request
    data = {
        "method": r.method,
        "url": r.pretty_url,
        "headers": dict(r.headers),
        "cookies": dict(r.cookies),
        "params": dict(r.query),
        "data": b64encode(r.raw_content).decode("ascii"),
    }
    scf_server = choice(scf_servers)          # 多地域/多函数 URL 轮换
    flow.request = flow.request.make(
        "POST", url=scf_server, content=json.dumps(data),
        headers={"SCF-Token": SCF_TOKEN, "Host": urlparse(scf_server).netloc,
                 "Connection": "close"},
    )

def response(flow):
    if flow.response.status_code == 200:
        resp = pickle.loads(b64decode(flow.response.content.decode("utf-8")))
        flow.response = flow.response.make(
            status_code=resp.status_code, headers=dict(resp.headers), content=resp.content,
        )
```

```text
启动：mitmdump -s client.py -p 9999 --no-http2
验证：目标应用代理指向 127.0.0.1:9999，访问回显源 IP 的站点，
     连续请求的源 IP 应互不相同且归属为云函数所在地域的云厂商网段。
```

## 变体与关联

- 出口池扩大：同一份代码部署到多个地域/多个云厂商的函数，`scf_servers` 列表随机取值；或每次调用前按需创建新函数实例。
- 客户端替换：不用 mitmproxy 也可以写成 requests 封装，或做成 SOCKS5 前端；mitmproxy 版本还能顺带做请求改写、header 注入与响应调试。
- 关联：`[[pentest-c2-faas-flask-proxy-traffic-forwarding]]` 同样借 FaaS 转发流量，但目的与形态不同——那张是给 C2 listener 做 redirector 隐藏真实基础设施（反向代理任意路径），本卡是把云函数当作**出网 IP 池**、由本地代理主动改写流量，解决的是"按源 IP 封禁/限速"。
- 边界：函数执行有超时（原文对 433 做专门提示），长连接/流式/WebSocket 类流量不适合；`--no-http2` 是必需的，HTTP/2 流在 JSON 重放下会失效；目标若按 TLS 指纹、Cookie、行为序列做风控，换 IP 无效；平台若限制出站白名单或禁止任意域名访问，该链不通。

## 检测与防御

- 检测（防守方视角）：同一业务在短时间内出现大量**不同源 IP、相同 UA/相同 header 顺序/相同 TLS 指纹**的请求，且源 IP 归属集中在少数云厂商网段——这是云函数代理池的典型特征；可按「云厂商 ASN + 高频 + 指纹一致」做聚合限速而不是单 IP 封禁。
- 检测（云平台/租户视角）：函数被用作开放代理的迹象是出站流量远大于入站、目标域名高度分散、单次调用时长贴近超时阈值；应在函数侧限制可访问的出站域名并审计。
- 防御：业务侧改用账号级/设备指纹级风控与会话一致性校验，而非只依赖源 IP；对云厂商 ASN 单独设定速率与验证要求（验证码、JS 挑战）；服务端对关键接口做包体与 header 一致性校验，识别被代理重放后失真的指纹（如 `Accept-Encoding`、`Connection` 被统一改写）。
