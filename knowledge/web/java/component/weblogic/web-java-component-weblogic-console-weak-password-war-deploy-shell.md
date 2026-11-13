---
id: web-java-component-weblogic-console-weak-password-war-deploy-shell
title: WebLogic 控制台默认弱口令登录 → 部署页安装恶意 WAR → JSP WebShell 获取 root 权限（原文 Docker 环境）
type: scenario
domain: web
path: web/java/component/weblogic
technique: weblogic-console-weak-password-war-deploy-webshell
aliases:
- WebLogic 弱口令
- weblogic Oracle@123
- console 部署 WAR getshell
- Weblogic 后台上传 war
- weblogic 默认口令
- weblogic shell.jsp 部署
tags:
- java
- weblogic
- weak-password
- console
- war-deploy
- webshell
- initial-access
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V664
  verified_at: '2026-11-13T08:09:45+08:00'
  notes: 已对照原文与img18-21核对：默认口令列表9组、weblogic/Oracle@123登录、部署→安装上传pack.war（img19/img20 状态活动健康OK）、访问/pack/shell.jsp冰蝎连接。修正：img21 whoami实为root（提示符/root/Oracle/Middleware/...），卡内原写oracle系与CVE-2018-2894节串扰，已改标题/正文/cards.json为root并注明生产环境可能以oracle运行。未验证点：未实际复现部署。
---

## 一句话结论

WebLogic 管理控制台 `/console/login/LoginForm.jsp` 若使用默认/弱口令（如 `weblogic/Oracle@123`、`system/password`、`wlcsystem/wlcsystem` 等），攻击者登录后在「部署」页安装一个包含 `shell.jsp` 的恶意 WAR 包，应用部署成功即把 JSP 发布到 Web 根（原文 `/pack/shell.jsp`），用冰蝎连接，以 WebLogic 进程身份（原文 Docker 环境为 `root`）执行命令——无需任何漏洞，纯配置缺陷即可 getshell。

## 原理

- **默认口令面**：WebLogic 安装/镜像/教学环境常保留默认管理员口令。原文列举常见组合：`system/password`、`weblogic/weblogic`、`admin/security`、`joe/password`、`mary/password`、`system/security`、`wlcsystem/wlcsystem`、`wlpisystem/wlpisystem`、`weblogic/Oracle@123`，并给出 cirt.net 的 weblogic 口令字典。
- **控制台部署功能**：管理员登录后进入「部署（Deployments）」→「安装（Install）」，可上传 WAR 包并部署到目标服务器。WAR 内的 JSP 会由 WebLogic 容器编译执行，访问路径为 `/<应用上下文>/shell.jsp`（原文 `pack.war` → `/pack/shell.jsp`）。
- **命令执行身份**：原文复现用的 vulhub WebLogic 10.3.6.0 容器中，WebLogic 以 `root` 运行，冰蝎 JSP WebShell 执行 `whoami` 返回 `root`（提示符 `/root/Oracle/Middleware/user_projects/domains/base_domain`）；生产环境若服务以 `oracle` 用户启动则获得对应普通用户权限。无论哪种身份都可读取 `user_projects/domains/base_domain` 下的配置与密钥文件。
- **为什么成立**：控制台部署功能本就是给管理员上传应用用的，弱口令把「管理员能力」直接暴露给攻击者；部署 WAR 是合法功能，不需要绕过任何安全机制。
- **凭据延伸**：WebLogic 的存储口令用 AES（老版本 3DES）加密，密钥材料在 `base_domain` 的 `SerializedSystemIni.dat` 与 `config.xml` 中；拿到这两个文件即可离线解密口令（见关联卡）。

## 触发条件

- 目标 WebLogic 控制台（默认 7001/console）可从攻击者网络访问。
- 管理员口令为默认/弱口令（或已在字典中）。
- 攻击者具备上传 WAR 的部署权限（弱口令登录的账号通常为管理员）。

## 利用步骤

1. 访问 `http://target:7001/console/login/LoginForm.jsp`，用常见默认口令尝试登录（原文 `weblogic/Oracle@123` 成功）。
2. 登录后进入「部署」→「安装」，准备包含 `shell.jsp`（冰蝎/蚁剑马）的目录，`jar -cvf pack.war .` 打包。
3. 在部署页上传 `pack.war`，按向导完成安装/激活（原文显示部署 `pack` 状态活动、健康 OK）。
4. 访问 `http://target:7001/pack/shell.jsp`，用冰蝎连接，执行 `whoami` 确认身份（原文 Docker 环境返回 `root`）。
5. 进一步读取 `user_projects/domains/base_domain` 下的 `config.xml`/`SerializedSystemIni.dat` 解密其他口令、横向或持久化。

## PoC

```bash
# 打包含 JSP 马的 WAR（在含 shell.jsp 的目录内）
jar -cvf pack.war .
# 控制台：部署 -> 安装 -> 上传 pack.war -> 激活
# 访问
curl http://target:7001/pack/shell.jsp
```

```text
# 常见默认口令（原文）
system/password
weblogic/weblogic
admin/security
joe/password
mary/password
system/security
wlcsystem/wlcsystem
wlpisystem/wlpisystem
weblogic/Oracle@123
```

## 变体与关联

- 变体：拿到控制台后也可开启「Web 服务测试页」再走 [[web-java-component-weblogic-cve-2018-2894-ws-utc-file-upload]]，或利用其他 console 功能落地。
- 关联：[[web-java-component-weblogic-jdbc-cipher-serializedsystemini-decrypt]]（`SerializedSystemIni.dat` + `config.xml` 解密 WebLogic 存储口令）、[[web-java-component-weblogic-cve-2020-14882-wls-console-path-traversal-mvel]]（无需口令的另一种 console 入口）。
- 边界：口令已改强、控制台仅管理网访问或启用了多因素时该链不可用。

## 检测与防御

- 检测：console 登录页来自异常 IP 的多次失败后成功；部署页新增 WAR/JSP；Web 根出现冰蝎/蚁剑访问特征；`user_projects` 目录被读取。
- 修复：立即修改默认口令并使用强口令；控制台不要暴露在公网（仅管理网/堡垒机）；删除无用应用与部署权限。
- 加固：启用控制台账户锁定/审计；定期轮换口令；对 `SerializedSystemIni.dat` 与 `config.xml` 做访问控制与完整性监控；部署操作告警。
