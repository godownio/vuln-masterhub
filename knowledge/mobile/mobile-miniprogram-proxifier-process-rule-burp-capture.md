---
id: mobile-miniprogram-proxifier-process-rule-burp-capture
title: Proxifier 进程规则抓 PC 微信小程序：WeChatApp 系列进程强制走 Burp HTTPS 代理
type: scenario
domain: mobile
path: mobile
technique: proxifier-process-rule-miniprogram-burp-capture
aliases:
- Proxifier 小程序抓包
- PC 微信小程序抓包
- WeChatApp 进程代理
- 微信小程序 HTTPS 抓包
- WeChatAppEx
tags:
- mobile
- miniprogram
- wechat
- proxifier
- burp
- proxy
- mitm
- https
- traffic-interception
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V641
  verified_at: '2026-11-13T02:24:27+08:00'
  notes: 非作者验证。核对依据：通读原文 3.3 节，逐张 Read 全部 28 张图（28/28 有效 JPEG，无失败）。img25 规则名「微信小程序流量转发」、应用程序 WeChatApp.exe; WechatBrowser.exe; WeChatAppEx.exe、动作 Proxy HTTPS 127.0.0.1:8080 与原文一致；img26 Burp Proxy Listener 127.0.0.1:8080；img27 Burp HTTP History 抓到 https://xxx-xyzw-res.hortorg.../remote/ui_xjzwFestival23/... 系列接口，并显示咸鱼之王小程序画面；img10/11 显示 java 规则可设为 Direct，对应原文 java 规则须 Direct 否则与 Burp 冲突。卡内已注明 Burp CA 导入系统受信任根为原文未展开的通用前提。原子性与查重：本卡对应原文 3.3（PC 微信小程序 Proxifier 进程级抓包），与卡1（frp 内网代理）、卡2（VMware 整机）不重复；dedup 中 mobile-miniprogram-charles-burp-upstream-proxy-capture 判 likely_duplicate/append_scenario，经比对该卡为 Charles 接管系统代理 + 全域名 SSL Proxying + External Proxy 转发 Burp 的另一条链，且其原文称 Proxifier 方案在其目标上未成功，与本卡按进程强制、无需系统代理、Burp 直接 MITM 的工具链/参数/触发条件均不同，属并列备选而非同一链，保留两卡便于对照；其余候选无关；dup-scan.json 不含本篇 pair。路径 mobile 存在，关联卡均存在。affected_versions 未设置（无组件版本语义）。未验证点：未在本机复跑；微信版本更名进程/证书固定情形需现场确认。
---

## 一句话结论

PC 微信的小程序/公众号流量由 `WeChatApp.exe`、`WechatBrowser.exe`、`WeChatAppEx.exe` 等独立进程发起，且不一定遵循系统代理；用 Proxifier 新建代理规则把这些进程的流量强制指向 Burp 的 HTTPS 监听（如 `127.0.0.1:8080`），即可在 Burp 的 HTTP History 中看到小程序接口的明文请求与响应；必须同时把 `java.exe/javaw.exe` 的规则设为 `Direct`（Burp 由 Java 启动，否则 Proxifier 会把 Burp 自身出站也代理，形成冲突/环路）。

## 原理

- PC 微信的小程序运行在独立渲染/宿主进程中（`WeChatApp.exe`、`WechatBrowser.exe`、`WeChatAppEx.exe`），其网络栈不保证走 Windows 系统代理，因此"给系统设置代理"不一定能抓到小程序流量。
- Proxifier 在内核/驱动层按"发起进程 + 目标地址"匹配连接，命中规则即重定向到代理服务器；这是进程级强制，与程序是否读取系统代理无关，所以能稳定命中微信小程序进程。
- Burp 作为 HTTPS 正向代理需要 TLS 中间人：客户端必须信任 Burp 的 CA 才能完成解密（PC 微信一般从 Windows 系统证书库取信任根，需先把 Burp CA 导入"受信任的根证书颁发机构"；原文未展开该步骤，但这是 HTTPS 抓包能看明文的前提）。
- `java.exe/javaw.exe → Direct` 的原因：Burp 本身是 Java 程序，若 java 进程也被规则代理到 Burp 自己，会产生"代理套代理"的环路/连接失败。规则从上到下匹配，java 的 Direct 规则需在代理规则之前。
- Intercept 需保持放行，否则流量卡在拦截页，小程序表现为请求超时。

## 触发条件

- Windows 主机登录 PC 微信，能打开目标小程序/公众号页面。
- Proxifier 与 Burp 就绪；Burp 监听 `127.0.0.1:8080`；Burp CA 已导入系统受信任根（或小程序进程信任该证书）。
- Proxifier 规则顺序正确：java 的 Direct 规则在代理规则之前；环回地址 Direct 规则置顶（避免本地通信用出问题）。
- 目标小程序未启用证书固定（pinning）；若启用则需额外 Frida/SSL unpinning 处理（超出本文范围）。

## 利用步骤

1. 按基础配置在 Proxifier 添加代理服务器：`HTTPS` 协议、`127.0.0.1:8080`（与 Burp Proxy Listener 一致），"检查"通过。
2. "代理规则 → 添加"，名称"微信小程序流量转发"，应用程序填：
   ```
   WeChatApp.exe; WechatBrowser.exe; WeChatAppEx.exe
   ```
   目标主机/端口保持"任意"，动作选 `Proxy HTTPS 127.0.0.1:8080`。
3. 确认 `java.exe; javaw.exe` 的规则动作为 `Direct`，并排在上述规则之前；环回规则（目标主机 `127.0.0.1; ::1`）置顶且为 `Direct`。
4. 打开 Burp，Proxy → Intercept 设为放行（不拦截或及时 Forward），观察 HTTP History。
5. 在 PC 微信中打开目标小程序，操作触发接口请求；Burp 中出现小程序的 HTTPS 请求（文章示例抓到 `xxx-xyzw-res.hortorg.../remote/ui_xjzwFestival23/...` 等接口）即可做改包/重放。
6. 若规则已生效仍无流量：检查证书信任、确认目标进程名（微信版本更新可能更换进程名）、查看 Proxifier 连接列表该进程的规则与代理命中情况。

## PoC

无脚本 PoC（纯 GUI 配置）。最小配置：
```
代理服务器: HTTPS 127.0.0.1:8080 (Burp)
规则1(置顶): 目标 127.0.0.1; ::1 → Direct
规则2: java.exe; javaw.exe → Direct
规则3: WeChatApp.exe; WechatBrowser.exe; WeChatAppEx.exe → Proxy HTTPS 127.0.0.1:8080
```

## 变体与关联

- 系统代理方案：Charles 开 Windows Proxy + 全域名 SSL Proxying + External Proxy 转发 Burp，见 [[mobile-miniprogram-charles-burp-upstream-proxy-capture]]；两者区别是本卡按进程强制、无需接管系统代理，适合微信不读系统代理的场景。
- 移动端/模拟器方案：手机/模拟器配合证书与代理抓 Android 微信小程序；企业微信/公众号同理可加 `WeChat.exe`、`WeChatWeb.exe` 等进程名。
- 后续利用：抓到接口后可继续做 wxapkg 解包（[[mobile-miniprogram-wxapkg-extract-unpack-toolchain]]）、签名算法逆向与重放（[[mobile-miniprogram-wxapkg-aes-cbc-sorted-sign-replay]]）。
- 关联：代理链与出网基础设施见 [[pentest-lateral-movement-proxifier-frp-socks5-process-rule-global-proxy]]。

## 检测与防御

- 检测（客户端安全视角）：终端上 `WeChatApp.exe` 等进程出现指向本地/非常规代理端口的连接；系统证书库新增未知根证书（Burp CA）。
- 防御（业务侧）：小程序接口对关键操作加签、绑定设备指纹，降低抓包改包重放价值；启用证书固定（pinning）与证书透明度校验。
- 防御（企业终端）：禁止安装 Proxifier 类网络劫持工具，监控根证书安装行为；对敏感小程序使用安全键盘/环境检测。
