---
id: web-generic-third-party-js-domain-takeover-night-redirect
title: 废弃第三方 JS 域名抢注投毒：bshare 分享插件夜间移动端强制跳转
type: scenario
domain: web
path: web/generic
technique: third-party-js-domain-takeover-night-redirect
tags:
- supply-chain
- third-party-script
- domain-takeover
- javascript
- redirect
- watering-hole
- web
- detection
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:17+08:00'
  notes: 已对照全文与 5 张图核对 bshare 公司注销/域名抢注、三文件 SHA1 一致、night_jump 夜间移动端跳转、24h Cookie、ASCII 编码与按天换域名；Hunter 6,399 IP/32,167 资产与 FOFA 60,794/12,071 与截图一致。未验证点：未执行恶意 JS、未核 WHOIS 时间线；抢注因果为原文陈述，confidence medium 合理；frontmatter 无 sources/source_url。
url: /docs/web/generic/web-generic-third-party-js-domain-takeover-night-redirect/
draft: false
kb_aliases:
- bshare 投毒
- 第三方 JS 投毒
- 废弃组件域名接管
- static.bshare.cn
- night_jump 夜间跳转
- 分享插件恶意跳转
---

## 一句话结论

第三方社交分享组件 bshare 的运营公司 2018 年注销后，其脚本域名 `static.bshare.cn` 被他人接管；大量网站多年未删除页面里的 `<script src="http://static.bshare.cn/b/...js">`，于是加载到被替换的恶意脚本——它检测移动端 UA、在北京时间 20:00–06:00 之间把访客强制跳转到 ASCII 编码隐藏的色情站，并用 Cookie 限制 24 小时内只跳一次、跳转域名按天更换，形成一条“废弃第三方组件 → 域名抢注 → 供应链投毒”的完整链路。

## 原理

- **第三方脚本以站点源执行**：页面引用外部 JS 时，脚本在站点自己的 origin 下运行，可读取/修改 DOM、Cookie 与 `window.location`；站点实际上把一部分前端控制权交给了第三方域名。
- **域名生命周期风险**：bshare 所属公司已于 2018-02-18 注销，`static.bshare.cn` 后续被他人抢注。原脚本虽在 2024-10-20 后已不可用，但引用它的 HTML 不会自动更新，域名新主人只要在原路径（`/b/bshareC0.js`、`/b/bshareCO.js`、`/b/buttonLite.js`）放置恶意 JS，所有仍引用该域名的站点就会在用户浏览器里执行攻击者代码。
- **恶意脚本的“夜间跳转”逻辑**：
  1. 用 `/iPhone|iPad|iPod|Android|Mobile/i` 判断移动端；
  2. 计算北京时间（`now + 60*timezoneOffset*1000 + 8h`），仅在北京时间 20:00–06:00 生效；
  3. 读取 Cookie `night_jump`，若无则写入 24 小时有效值，避免同一用户反复跳转、降低暴露；
  4. 把目标 URL 用十进制 ASCII 数组隐藏（如 `[104,116,...]` → `https://s5.xxxxxx.com`），再 `window.location.href = 解码后的 URL`。
- **为什么难以用哈希查杀**：恶意域名与跳转地址按天更换（示例 Day1 `https://s5.rbstudy.com/?s5`，Day2 `https://s5.nbcmzn.com`），三个 JS 文件名内容一致（SHA1 均为 `3ca19931c856ea83d5b577064364506db42e23a4`）但域名会变；只比对固定 md5/域名会漏掉新变种。
- **影响面**：用 Hunter `web.body="static.bshare.cn"` 与 FOFA `body="static.bshare.cn"` 可检索到数千独立 IP、数万资产仍引用该脚本；攻击者无需入侵任何站点，只靠一个过期域名即可批量影响这些站点。
- **为什么选夜间**：夜间业务与安全监控相对薄弱，移动端用户占比高，强制跳转到色情/赌博站可获取流量或广告收益；Cookie 节流则让单用户不易察觉。

## 触发条件

- 网站 HTML 中仍引用 bshare 的 `static.bshare.cn/b/bshareC0.js`、`bshareCO.js` 或 `buttonLite.js`（或该域下其他脚本），且未配置 SRI/CSP 限制。
- `static.bshare.cn` 已被攻击者控制，并在原路径返回恶意 JS。
- 访客使用移动端浏览器，本地时间为北京时间 20:00–06:00，且 24 小时内未触发过 `night_jump` Cookie。
- 页面允许第三方脚本执行（无严格 CSP `script-src` 白名单/沙箱）。

## 利用步骤

1. **发现废弃组件**：用 Hunter/FOFA 语法 `web.body="static.bshare.cn"` / `body="static.bshare.cn"` 批量检索仍引用该域名的站点；也可在目标页面源码中搜索 `bshare.cn`、`bshareC0.js`、`buttonLite.js`。
2. **确认域名归属**：查询域名 WHOIS/备案/公司状态，确认原运营方已注销、域名已过期或被重新注册；访问原 JS 路径看是否仍返回内容、内容是否与历史版本不同。
3. **接管与投毒**：注册/控制过期域名，在原路径部署恶意 JS；保持与原脚本相同的文件名和可访问路径，降低引用方察觉。
4. **植入跳转逻辑**：按 UA + 北京时间夜间窗口 + Cookie 节流筛选受害者；目标 URL 用 ASCII 数组或 Base64 等编码隐藏，并按天/按批次轮换落地域名，规避域名黑名单。
5. **验证**：在移动端 UA、模拟北京时间 20:00 后访问引用站点，观察是否 302/JS 跳转；清除 `night_jump` Cookie 可重复触发。
6. **清理痕迹/扩大**：脚本不落地文件、不修改站点内容，仅在浏览器执行；可进一步替换为钓鱼页、挖矿脚本或凭证窃取代码。

## PoC

```javascript
// 恶意脚本核心逻辑的可读等价写法（非原文逐字）
const MOBILE = /iPhone|iPad|iPod|Android|Mobile/i.test(navigator.userAgent);
const beijingHour = new Date(Date.now() + 8 * 3600 * 1000).getUTCHours();
const NIGHT = beijingHour >= 20 || beijingHour < 6;
const jumped = document.cookie.split("; ").some(v => v.startsWith("night_jump="));

// 目标地址用十进制 ASCII 数组隐藏：https://s5.xxxxxx.com
const target = [104,116,116,112,115,58,47,47,115,53,46,110,98,99,109,122,110,46,99,111,109]
  .map(c => String.fromCharCode(c)).join("");

if (MOBILE && NIGHT && !jumped) {
  document.cookie = "night_jump=1; expires=" + new Date(Date.now() + 24*3600*1000).toUTCString() + "; path=/";
  window.location.href = target;
}
```

```text
# 三个投毒文件（原文哈希一致）
bshareC0.js / bshareCO.js / buttonLite.js
SHA1: 3ca19931c856ea83d5b577064364506db42e23a4
# 跳转域名按天更换示例
Day1: https://s5.rbstudy.com/?s5
Day2: https://s5.nbcmzn.com
```

说明：PoC 为原文恶意脚本行为的结构化复现，未执行；原文截图显示引用页面加载 `static.bshare.cn` 的脚本、ASCII 解码得到跳转地址，以及站点被跳转到色情页面。

## 变体与关联

- 变体（载体）：其他废弃的分享按钮、统计代码、客服插件、广告/联盟 JS、jQuery 插件 CDN；只要域名过期且被引用，都可能被同样接管。
- 变体（投毒内容）：强制跳转、钓鱼登录页、加密货币挖矿、凭证/表单窃取、广告注入、DDoS 脚本。
- 变体（规避）：UA/地域/时间窗筛选、Cookie/ localStorage 节流、ASCII/Base64/自定义编码隐藏 URL、按天轮换域名、只在特定 referer 下触发。
- 关联：[[pentest-initial-access-fake-chrome-update-watering-hole]]、[[pentest-initial-access-internal-software-download-replacement-watering-hole]]（水坑/供应链投递思路）；[[pentest-recon-search-engine-directory-listing-redteam-tool-hunting]]（空间搜索引擎资产发现）；[[web-generic-xss-csp-self-jsonp-callback-bypass]]（CSP 绕过与脚本执行边界）。
- 边界：站点已删除引用、启用 SRI（integrity 哈希不匹配会拒绝执行）、CSP `script-src` 仅允许可信源、或域名仍由原厂商控制时，投毒不成立；桌面端/非夜间/已有 Cookie 的用户不会触发。

## 检测与防御

- 资产自查：全站/全网搜索页面源码中的 `static.bshare.cn`、`bshareC0.js`、`bshareCO.js`、`buttonLite.js`、`bshare.cn`；用 `grep -R`/爬虫/CDN 日志梳理外部脚本清单；对第三方域名做 WHOIS、备案、公司存续和证书到期监控。
- 检测恶意行为：`night_jump` Cookie、移动端 UA 下的异常 `window.location` 跳转、ASCII 数组解码后的外链、页面加载后立即跳转到陌生域名；浏览器端监控 `location` 变更与 `document.cookie` 写入。
- 检测脚本内容：不要只比对 md5/域名（会轮换）；按文件名、`night_jump`、ASCII 数组特征、`location.href` 赋值等关键词做内容检测；对下载的 JS 做去混淆与人工复核。
- 防御：删除不再使用的第三方组件；必须使用时自托管并固定版本、加 SRI、CSP `script-src` 白名单/`strict-dynamic`；定期扫描外部依赖与过期域名；在网关/WAF 拦截已知恶意域名，浏览器插件/EDR 侧阻断异常跳转；对用户做钓鱼/跳转告警。
