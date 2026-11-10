---
id: mobile-miniprogram-charles-burp-upstream-proxy-capture
title: 微信小程序抓包：Charles 系统代理 + 全域名 SSL Proxying 后上游转发 Burp 的双代理链
type: scenario
domain: mobile
path: mobile
technique: miniprogram-charles-upstream-burp-proxy-chain
aliases:
- 微信小程序抓包
- Charles 转发 Burp
- Charles External Proxy
- 双代理链抓包
- Windows 微信小程序 抓包
- WeChat mini program traffic capture
tags:
- miniprogram
- wechat
- charles
- burp
- proxy
- mitm
- https
- traffic-interception
- mobile
- pentest
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V333
  verified_at: '2026-11-08T18:28:15+08:00'
  notes: 已对照原文与10/10张图核对：img01-02 根证书装入受信任的根证书颁发机构；img04 Charles HTTP 8888、SOCKS 8889、Support HTTP/2；img06 SSL Proxying Enable 且 Host=* Port=*；img08 External Proxy 勾选后 HTTP/HTTPS 均 127.0.0.1:8091（未勾选 bypass localhost）；img09 Burp 监听 127.0.0.1:8091 且绑定地址为仅限回环；img10 Burp 中可见带 MiniProgramEnv/Windows WindowsWechat/WMPF UA 的明文 POST，JSON 含 user_id/app_id/页面参数，链路闭环成立。判定：非纯安装教程——安装步骤已剔除，保留的是可复用的 Charles 系统代理+TLS 解密+上游 Burp 双代理抓包技巧，属移动测试流量拦截手法，保留。未验证点：未在本机复跑该配置；原文未给出其他抓包方式失效的根因；未涉及证书固定/mTLS，卡内已在边界注明。工具版本 Charles 4.6.2/Burp 2023 为目标环境非受影响版本，已 --clear；无 sources/source_url/文章 ID/长段摘录，path mobile 合法，关联卡 id 均存在。
---

## 一句话结论

在 Windows 上抓微信小程序 HTTPS 流量时，让 Charles 作为系统代理并开启 `*:*` 全域名 SSL Proxying，再把 Charles 的 External Proxy 指到 Burp 的 `127.0.0.1:8091`，即可由 Charles 完成系统代理接管与 TLS 解密、Burp 直接收到明文请求并做拦截/改包/重放；原文用该链路成功抓到小程序业务接口的 JSON 请求。

## 原理

- **Charles 接管系统代理**：开启 `Proxy → Windows Proxy` 后，Charles 监听 HTTP 8888（可同时开 SOCKS 8889），Windows 上走系统代理的微信小程序请求先到 Charles。
- **Charles 做 TLS 中间人**：Charles 用自身根证书对 HTTPS 重新签名，前提是把 `Charles Root Certificate` 安装进 Windows「受信任的根证书颁发机构」；否则小程序/系统不信任该证书，握手失败。
- **全域名解密**：`SSL Proxying Settings` 勾选 Enable SSL Proxying 并 `Add Host=* Port=*`，Charles 才会对所有 host/port 解密，而不是只对 CONNECT 隧道透传密文。
- **上游转发 Burp**：`External Proxy Settings` 勾选 Use external proxy servers，Web Proxy（HTTP）与 Secure Web Proxy（HTTPS）都填 `127.0.0.1:8091`；Burp 在同一端口建监听。Charles 解密后以普通 HTTP 转发，Burp 看到的是明文请求，不需要再处理小程序的证书链。
- 为什么两层：Charles 擅长系统代理接管与 TLS 解密，Burp 擅长拦截、Repeater/Intruder 与插件生态；串联后两者能力叠加。原文称直接 Burp+Proxifier、Burp+安卓模拟器等方案在该小程序上抓不到，但未给出根因分析（可能与客户端不遵循对应代理路径/证书信任有关）。
- 影响：一旦解密成功，小程序的登录态、用户标识、业务参数等明文请求全部可见，可进一步做越权、重放与参数篡改测试。

## 触发条件

- 目标为 Windows 微信中的小程序（原文抓到的 UA 含 `MiniProgramEnv/Windows WindowsWechat/WMPF`）。
- 攻击者有本机管理员权限，可安装 Charles 根证书到 Windows 受信任根存储。
- 小程序未启用证书固定/双向认证等额外防护（原文未涉及；启用时该链路只能看到 TLS 失败或需另行绕过）。
- 本机可运行 Charles 4.6.2 与 BurpSuite 2023，且系统代理可被修改。

## 利用步骤

1. 安装 Charles 根证书：`Help → SSL Proxying → Install Charles Root Certificate`，在证书导入向导选择「将所有的证书都放入下列存储 → 受信任的根证书颁发机构」。
2. 配置 Charles 代理：`Proxy → Proxy Settings`，HTTP Proxy 端口 8888（勾选 Support HTTP/2/Enable transparent HTTP proxying），按需启用 SOCKS 8889。
3. 打开全域名解密：`Proxy → SSL Proxying Settings`，勾选 Enable SSL Proxying，Add `Host: *`、`Port: *`。
4. 配置上游代理：`Proxy → External Proxy Settings`，勾选 Use external proxy servers，`Web Proxy (HTTP)` 与 `Secure Web Proxy (HTTPS)` 均填 `127.0.0.1:8091`。
5. 配置 Burp 监听：`Proxy → Proxy settings → Add`，绑定端口 8091，绑定地址选「仅限回环地址」。
6. 勾选 Charles 的 `Proxy → Windows Proxy`，让系统流量进入 Charles。
7. 打开微信小程序操作功能，在 Burp 的 Proxy HTTP history 中查看小程序请求；原文示例为 POST 业务接口，JSON 体含 `user_id`、页面参数与 `app_id` 等字段。

## PoC

无脚本型 PoC；最小复现为上述配置组合，关键参数如下：

```text
Charles HTTP proxy      : 8888
Charles SSL Proxying    : Host=*  Port=*
Charles External Proxy  : HTTP 127.0.0.1:8091 / HTTPS 127.0.0.1:8091
Burp listener           : 127.0.0.1:8091 (loopback only)
```

验证：Burp 中收到 `User-Agent: ... MiniProgramEnv/Windows WindowsWechat/WMPF` 的明文请求即链路生效；若小程序请求缺失，依次检查证书是否在受信任根、SSL Proxying 是否为 `*:*`、Burp 监听端口与 External Proxy 是否一致。

## 变体与关联

- 变体（端口/工具）：上游代理可换成 mitmproxy/Reqable，Charles 也可只做系统代理；关键是「前端负责系统代理+TLS 解密，后端负责改包」的分工。
- 变体（目标平台）：Android/iOS 微信小程序需对应平台的系统证书安装与 SSL pinning 绕过。
- 关联：[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]（小程序国密 SM2/SM3/SM4 协议逆向与 Burp 透明加解密）；[[mobile-android-ssl-pinning-bypass-cert-frida]]（Android 证书固定绕过）；[[mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration]]（抓到流量后的参数加密与签名重算）。
- 边界：小程序启用证书固定、mTLS 或私有协议加密时，仅靠该代理链无法得到可读业务数据；需先做 pinning 绕过或协议逆向。

## 检测与防御

- 检测特征：客户端出现非预期根证书信任、请求经代理转发；服务端可见异常来源 IP/延迟与代理特征头（需结合业务风控）。
- 防御：小程序启用证书固定/双向认证；敏感接口做请求签名（时间戳+nonce+密钥）与防重放；对登录态绑定设备指纹/风控；避免在客户端暴露长期有效的凭据。
- 测试侧注意：仅在授权范围内抓包；Charles/Burp 根证书测试后及时移除，避免污染本机信任链。
