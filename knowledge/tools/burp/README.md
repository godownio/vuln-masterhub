# Burp Suite

## 这层是什么

插件、拦截、扫描与扩展。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [autoDecoder + Flask 中间层 + Sekiro 浏览器 JSRPC：不还原前端 AES 算法，运行时调用页面加解密函数实现 Burp 请求/响应透明加解密](tools-burp-autodecoder-flask-sekiro-jsrpc-body-encrypt-decrypt.md) | verified | high | 2026-11-11 |
| [autoDecoder 内置加解密主体 + 正则提取：表单与 JSON 两种密文载体的配置差异，覆盖固定 AES key、服务端下发不变 key、RSA 公钥单向加密三类登录爆破](tools-burp-autodecoder-builtin-regex-form-json-rsa-login.md) | verified | high | 2026-11-08 |
| [autoDecoder 接口加密与 captcha-killer-modified 双插件串联：Pitchfork 按扩展生成验证码、按脚本实时 md5 加密口令爆破加密登录口](tools-burp-autodecoder-captcha-killer-pitchfork-encrypted-bruteforce.md) | verified | medium | 2026-11-09 |
| [autoDecoder 自定义加解密脚本：Flask /encode /decode 接口、bytes/str 与 Base64 编码、PKCS 填充及 JSON 字段处理](tools-burp-autodecoder-flask-custom-encrypt-decrypt-script.md) | verified | high | 2026-11-07 |
| [Burp HaE 自定义正则被动标记与提取流量中的云 AccessKey/敏感字段：提取分组必须加括号、scope/exclude 配置与 20+ 厂商 AK 正则集](tools-burp-hae-regex-accesskey-sensitive-highlight.md) | verified | medium | 2026-11-11 |
| [Burp Jython 插件按域名/路径丢弃请求（Request Dropper）：IHttpListener 过滤 + ITab 配置面板 + 空请求替换](tools-burp-jython-request-dropper-http-listener.md) | verified | high | 2026-11-09 |
| [Burp Montoya API 自研扩展最小骨架：BurpExtension 初始化、Suite Tab 注册与 ContextMenuItemsProvider 右键菜单](tools-burp-montoya-extension-skeleton-suite-tab-context-menu.md) | verified | high | 2026-11-08 |
| [Burp SignMe 插件用 GraalVM JS 规则重算 Hash 签名与时间戳：把「签名错误」的支付接口变成可改包可爆破的明文接口](tools-burp-signme-graalvm-js-rule-hash-sign-replay.md) | verified | high | 2026-11-08 |
| [Burp 代理检测与指纹消除：http://burp/favicon.ico 跨域 img onload 探测，及删 favicon/代理例外/关闭 Web 接口三种规避](tools-burp-favicon-proxy-detection-removal.md) | verified | high | 2026-11-09 |
| [BurpCrypto ExecJs 搭配 webpack/ESM 产物抠取 md5 函数：按 import 别名定位 export 真名，逐请求重算签名并整体构造请求体](tools-burp-burpcrypto-execjs-webpack-md5-function-extract-sign.md) | verified | high | 2026-11-10 |
| [Burpy：Burp 经 PyRO 调用 Python 脚本自动加解密请求/响应（Burpy 类接口与三个常见报错）](tools-burp-burpy-pyro-python-auto-encrypt-decrypt.md) | verified | high | 2026-11-07 |
| [Galaxy + JsRpc 透明加解密与动态签名：Burp hook 自动改包重放](tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign.md) | verified | high | 2026-11-08 |
| [Galaxy Montoya HttpHook 四段拦截 + 动态密钥捕获：/api/getSecret 响应解析后自动加解密](tools-burp-galaxy-http-hook-dynamic-key-capture.md) | verified | high | 2026-11-08 |
| [Hermes Agent 接入 Burp MCP：WSL 端口桥接、Origin 403 与异步 SSE 排障](tools-burp-hermes-mcp-wsl-sse-integration.md) | verified | high | 2026-11-05 |
| [JS Hook + 本地 Bridge + Burp 扩展：不还原算法直接加解密 Web 流量](tools-burp-js-hook-bridge-traffic-encrypt-decrypt.md) | verified | high | 2026-11-06 |
| [mitmdump addon 断点调试：用 Python 启动器内嵌调用 mitmdump([...]) 启动，-s 脚本即可在 IDE 下断点](tools-burp-mitmdump-addon-launcher-breakpoint-debug.md) | verified | high | 2026-11-12 |
| [mitmproxy 上下游双代理链把 AES-CBC 加密接口还原成明文，再用 Yakit 热加载 codec.AESCBCEncryptWithPKCS7Padding + x"{{payload(phone)}}" fuzztag 批量加密字典爆破手机号](tools-burp-mitmproxy-dual-chain-aes-cbc-yakit-hotload-phone-bruteforce.md) | verified | high | 2026-11-09 |
| [OneScan 递归目录扫描 + 代理被动流量：逐层拼接字典并把扫描 GET 改造成 POST，配合摘头/替头批量初筛未授权与越权](tools-burp-onescan-recursive-dir-scan-proxy-unauth-screen.md) | verified | high | 2026-11-08 |
| [加密 API 测试代理链：上下游 mitmproxy 透明解密/重签，绕过防重放与 AES 参数加密](tools-burp-encrypted-api-proxy-decrypt-resign.md) | verified | high | 2026-11-06 |
| [加密/自定义包装 body 的 Burp+xray 联动扫描：autoDecoder 解密并改写成纯 JSON 交给 xray，burp2 还原包装并重加密后发给服务端](tools-burp-autodecoder-xray-encrypted-body-adapter-scan.md) | verified | high | 2026-11-13 |
| [自研 Burp Montoya + PyRO 桥接插件：ProxyRequestHandler 拦截加解密 + watchdog 热加载 Python + config 分项目](tools-burp-montoya-pyro-python-hot-reload-bridge.md) | verified | medium | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
