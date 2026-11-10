---
id: cloud-cloud-iam-okta-malicious-saml-idp-assertion-any-user
title: Okta 注册恶意 SAML IdP：自签证书 + 客户端转发 SSO URL 劫持，伪造任意用户断言免凭据登录
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: okta-malicious-saml-idp-assertion-any-user
tags:
- okta
- cloud-iam
- saml
- identity-provider
- assertion-forgery
- authentication-bypass
- admin-abuse
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:13:10+08:00'
  notes: 已对照原文与截图核对：添加 SAML 2.0 IdP、Issuer URI https://www.example.com/、自签证书 CN=idp.google.com、Match against=Okta Username or Email、Account Link Policy=Automatic、下载 metadata、ACS URL https://example.okta.com/sso/saml2/<idpId>、hosts 指向 127.0.0.1 的 idp.google.com/saml 自制服务器、任意邮箱登录均与原文一致；原文也提示 Okta 已提供安全更新。未验证点：Okta 现行版本对该注册手法的限制需实测。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-okta-malicious-saml-idp-assertion-any-user/
draft: false
kb_aliases:
- 假 SAML IdP
- Okta 外部 IdP 滥用
- SAML 断言伪造
- IdP 签名证书
- hosts 劫持 SSO URL
- Okta 任意用户登录
---

## 一句话结论

拿到有外部 IdP 管理权限的 Okta 账户后，注册一个由自己控制签名证书的 SAML 2.0 IdP（IdP SSO URL 可指向任意域，因为 SAML 请求由客户端浏览器转发），把匹配设为 Okta 用户名/邮箱、账户关联设为自动，再访问 ACS URL 触发认证，在自己的 SAML 服务器上为任意邮箱签发断言，即可无凭据登录为任意 Okta 用户。

## 原理

- Okta 允许管理员添加外部 SAML 2.0 IdP，并把管理员上传的证书作为该 IdP 的签名验证根；私钥在攻击者手里时，攻击者可以签任意 Subject 的 SAML 断言，Okta 都会认为来自可信 IdP。
- IdP SSO URL 不必是攻击者控制的服务器：Okta 生成 SAML AuthRequest 后让浏览器 302 重定向到该 URL，请求在客户端侧转发。因此可以填写 `idp.google.com` 这类合法域名，再改本地 hosts 指向 127.0.0.1 上的 SAML 服务器接收 AuthRequest，既完成了攻击，也让流量看起来指向可信域。
- 签名证书可是自签名，CN 可写成 `idp.google.com`；Okta 不验证证书的真实性，只要求上传并可被 Okta 用来验签。
- 把 "Match against" 设为 Okta Username or Email、Account Link Policy 设为 Automatic 后，断言里的身份会自动关联到已存在的 Okta 用户，无需预先在 IdP 侧配置用户。
- 访问 ACS URL（`https://<tenant>.okta.com/sso/saml2/<idpId>`）会启动登录流程：Okta 生成 AuthRequest 并重定向到 IdP SSO URL；攻击者的 SAML 服务器返回带签名的认证响应，Okta 验签通过后建立该用户会话。全程不需要用户口令或 MFA。

## 触发条件

- Okta 管理员账户或有外部 IdP 管理权限的账户。
- 租户允许添加 SAML 2.0 IdP，且未对该攻击做限制（文章发布时 Okta 已针对该手法提供安全更新，需确认版本/配置）。
- 攻击者能生成自签证书、运行 SAML 服务器，并能修改本地 hosts/DNS 或控制 IdP SSO URL 域名。
- 目标 Okta 用户已存在（自动关联策略要求匹配到现有用户）。

## 利用步骤

1. 在 Okta 管理后台添加 SAML 2.0 IdP：Issuer URI 任意填写（如 `https://www.example.com/`），IdP SSO URL 填一个可信域名（如 `https://idp.google.com/saml`）。
2. 用 OpenSSL 生成自签名证书/私钥，CN 设为 SSO 域名（如 `idp.google.com`），上传证书到 Okta。
3. 设置 Match against = Okta Username or Email，Account Link Policy = Automatic，保存并下载 metadata，记录 IdP ID 与 ACS URL。
4. 在攻击机 hosts 中把 SSO 域名指向 127.0.0.1，启动能接收 SAML AuthRequest 并签发断言的自定义 SAML IdP 服务器。
5. 浏览器访问 ACS URL，Okta 重定向到 IdP SSO URL，本地 SAML 服务器收到 AuthRequest。
6. 在服务器上输入目标用户邮箱，签发对应 Subject 的签名 SAML 响应返回 Okta，即可登录为任意用户。
7. 后续可访问该用户可用的所有 Okta 应用。

## PoC

```bash
# 1) 自签 IdP 证书（CN 与 SSO 域名一致）
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout idp.key -out idp.crt -subj "/CN=idp.google.com"

# 2) 本地劫持 SSO 域名，指向自制 SAML 服务器
echo '127.0.0.1 idp.google.com' | sudo tee -a /etc/hosts

# 3) Okta 后台添加 SAML 2.0 IdP，上传 idp.crt，
#    Match against = Okta Username or Email，Account Link Policy = Automatic
# 4) 访问 ACS URL（https://<tenant>.okta.com/sso/saml2/<idpId>）
#    本地的 idp.google.com 收到 SAMLRequest 后，为任意邮箱返回签名断言
```

## 变体与关联

- 关联 [[web-generic-xxe-saml-acs-parse-before-signature]]、[[web-java-component-vcenter-saml-data-mdb-cert-cookie-forgery]]：那些是 SAML 解析/证书校验实现漏洞；本卡滥用的是 Okta 管理员合法配置能力，攻击面在“谁能注册 IdP + 证书信任”。
- 变体：若 SSO URL 指向攻击者自有域名，则不需要 hosts 劫持，直接接收 AuthRequest；hosts 版主要用于红队演示/规避域名审查。
- 边界：需要管理员权限；账户关联策略若为手动则需目标用户已由 IdP 预配；Okta 的安全更新可能限制/告警此类注册。

## 检测与防御

- Okta 审计：监控 Identity Provider 创建、签名证书上传、Issuer/SSO URL 变更与自动账户关联策略的修改；对 SSO URL 指向非企业域名/自签证书的配置强制审核。
- 权限治理：最小化可管理 IdP 的管理员数量，启用管理员 MFA 与条件访问；对 IdP 配置变更引入双人审批。
- 防御：要求 IdP metadata 签名或证书链校验、限制外部 IdP 的域名白名单；对通过外部 IdP 登录的用户做异常检测（新 IdP、异常时间、来源 IP）。
- 验证：定期审计现有 IdP 的证书指纹与 SSO URL 是否符合预期，发现自签或可疑域名立即禁用。
