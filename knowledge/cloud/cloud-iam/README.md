# 云 IAM

## 这层是什么

权限提升、角色链、跨账号与策略缺陷。

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
| [AWS IAM 危险权限组合提权：CreateAccessKey、CreateLoginProfile、AttachUserPolicy 与 PassRole](cloud-cloud-iam-aws-dangerous-permission-privesc.md) | verified | medium | 2026-11-05 |
| [AWS 后门角色持久化：新建角色 trust 策略只信任后门用户 + 附加 AdministratorAccess，用后门用户的长期 AK 反复 sts assume-role 换管理员临时凭证](cloud-cloud-iam-aws-backdoor-role-assume-role-persistence.md) | verified | high | 2026-11-08 |
| [AWS 后门身份自建：create-user + attach-user-policy AdministratorAccess + create-access-key 形成独立于原凭证轮换的持久管理员 AK](cloud-cloud-iam-aws-backdoor-user-key-persistence.md) | verified | high | 2026-11-08 |
| [Azure PowerShell TokenCache.dat 明文令牌窃取：从用户 .Azure 目录读取 AccessToken/RefreshToken 复用云端资源](cloud-cloud-iam-azure-powershell-tokencache-plaintext-token.md) | verified | medium | 2026-11-13 |
| [CodeCommit 分支与提交历史挖掘硬编码 AK/SK：list-repositories/get-commit/get-differences/get-file 读取 dev 分支源码中的云凭据](cloud-cloud-iam-codecommit-branch-commit-history-secret-mining.md) | verified | high | 2026-11-13 |
| [Cognito 身份池匿名/用户池开放注册取 AWS 临时凭证：用 Lambda 参数 SSRF 读 /proc/self/environ 获取环境变量 AK/SK](cloud-cloud-iam-cognito-unauth-userpool-lambda-ssrf-env.md) | verified | medium | 2026-11-13 |
| [Entra Connect Sync_* 账户滥用：私有 Azure AD Synchronization API 重置混合用户密码](cloud-cloud-iam-entra-connect-sync-account-password-reset-private-api.md) | verified | high | 2026-11-07 |
| [Entra ID DSA 角色隐藏持久化：Directory Synchronization Accounts 赋权、查询与移除](cloud-cloud-iam-entra-connect-dsa-role-hidden-persistence.md) | verified | high | 2026-11-07 |
| [Entra ID 会话接管：注入 ESTSAUTH/ESTSAUTHPERSISTENT Cookie 复用已认证云会话](cloud-cloud-iam-entra-id-session-cookie-replay.md) | verified | high | 2026-11-07 |
| [Entra ID 动态组 Guest 自动入组：User.Invite.All 邀请外部账号继承组上的应用角色](cloud-cloud-iam-entra-dynamic-group-guest-invite-app-role.md) | verified | high | 2026-11-06 |
| [Entra ID 管理员同意链：common 端点枚举租户 ID + Graph 查 redirect_uri + adminconsent 获取应用权限](cloud-cloud-iam-entra-tenant-id-redirect-uri-adminconsent.md) | verified | high | 2026-11-06 |
| [Lambda 环境变量泄漏长期 AWS AK：enumerate-iam 枚举权限后从 Secrets Manager 读取敏感值](cloud-cloud-iam-lambda-env-ak-enumerate-secrets-manager.md) | verified | medium | 2026-11-12 |
| [Nacos 配置详情泄露阿里云 OSS AK/SK：控制台/oss-browser 接管存储桶](cloud-cloud-iam-nacos-config-aliyun-ak-sk-oss-takeover.md) | verified | medium | 2026-11-08 |
| [Okta AD Agent 接管：DPAPI 解密 AgentToken 后走内部 API，nextAction 捞明文口令 / actionResult 批准任意登录](cloud-cloud-iam-okta-ad-agent-token-dpapi-credential-capture-skeleton-key.md) | verified | high | 2026-11-09 |
| [Okta 委托认证 Silver Ticket：用代理账户 AES 密钥为任意用户伪造 TGS，浏览器提交即认证为受害者](cloud-cloud-iam-okta-delegated-auth-silver-ticket-aes-any-user.md) | verified | high | 2026-11-09 |
| [Okta 委托认证（Agentless DSSO）：dig/LDAP 发现 Kerberos SPN，注入 AD 用户 TGS 直接登录 Okta 并绕过 MFA](cloud-cloud-iam-okta-agentless-dsso-kerberos-tgs-login.md) | verified | high | 2026-11-09 |
| [Okta 注册恶意 SAML IdP：自签证书 + 客户端转发 SSO URL 劫持，伪造任意用户断言免凭据登录](cloud-cloud-iam-okta-malicious-saml-idp-assertion-any-user.md) | verified | high | 2026-11-09 |
| [Okta 管理员伪造 AD Agent：借 AD Agent OAuth 客户端换取 api_token，内部 API 注册假连接器后捕获/批准任意认证](cloud-cloud-iam-okta-fake-ad-agent-admin-oauth-token-registration.md) | verified | high | 2026-11-09 |
| [S3 备份泄露 SSH 私钥 + EC2 GetPasswordData：解密 Windows 实例 Administrator 口令，登录后取实例内 .aws 凭据并导出 ntds.dit](cloud-cloud-iam-s3-ssh-key-ec2-getpassworddata-windows-admin.md) | verified | high | 2026-11-13 |
| [S3 桶匿名枚举 + shared 目录脚本/export.xml 凭据泄露 → 换管理员 AK/SK 读取 admin/flag.txt](cloud-cloud-iam-s3-anonymous-enum-export-xml-privilege-escalation.md) | verified | high | 2026-11-08 |
| [S3 桶名规律爆破获取桶内源码硬编码 AK/SK：SSM Parameter Store 取次级凭据后调用 Lambda 读取 flag](cloud-cloud-iam-s3-bucket-name-brute-source-ssm-lambda.md) | verified | high | 2026-11-13 |
| [S3 桶策略只校验 aws:SourceVpce 时，用泄露凭证预签名并经 VPC 内 SSRF 读取私有对象](cloud-s3-presigned-url-vpce-bypass.md) | verified | high | 2026-11-05 |
| [STS Policy 注入黑名单绕过：字符串双写与 JSON Unicode 转义恢复被过滤的 Action/通配符](cloud-cloud-iam-sts-policy-injection-filter-bypass-unicode.md) | verified | medium | 2026-11-05 |
| [STS Policy 注入：可控 Object Key 进入 AssumeRole 会话 Policy 导致临时凭据越权](cloud-cloud-iam-sts-policy-injection-object-key.md) | verified | high | 2026-11-05 |
| [ThinkCMF 后台插件设置泄露七牛云 AK/SK：qshell/SDK 验证后接管 48.92GB 存储空间并跨子域读取文件](cloud-cloud-iam-thinkcmf-qiniu-ak-sk-bucket-takeover.md) | verified | high | 2026-11-08 |
| [云工作负载凭据的 IAM 策略自助枚举与危险权限判定](cloud-cloud-iam-workload-role-policy-selfcheck.md) | verified | high | 2026-11-05 |
| [从公开 S3 桶枚举 AWS Account ID：AssumeRole + 桶策略权限 oracle（s3-account-search）](cloud-cloud-iam-s3-account-id-enumeration-assumerole-oracle.md) | verified | high | 2026-11-08 |
| [公开 S3 备份泄漏 AK → DynamoDB scan 拖用户表 → hashcat 破解 → AWS 控制台口令喷洒接管账号](cloud-cloud-iam-s3-backup-ak-dynamodb-scan-console-password-spray.md) | verified | high | 2026-11-13 |
| [前端 JS 泄露阿里云长期 AK/SK：OSS 桶枚举、ECS 导入与云资产接管](cloud-cloud-iam-frontend-js-alibaba-ak-sk-cloud-takeover.md) | verified | medium | 2026-11-07 |
| [前端签名可复现的 OSS 上传配置接口：伪造 MD5 签名获取阿里云 STS 并接管对象存储](cloud-cloud-iam-frontend-sign-replay-uploadossdata-sts-bucket-takeover.md) | verified | high | 2026-11-09 |
| [华为云 OBS 桶策略 SourceIp 限制绕过：伪造 X-Forwarded-For 内网地址即可列对象](cloud-obs-bucket-policy-sourceip-xff-spoof-bypass.md) | verified | high | 2026-11-13 |
| [搜索引擎批量发现泄露的 AWS AK/SK 并接管云权限](cloud-cloud-iam-aws-access-key-leak-search-engine-takeover.md) | verified | high | 2026-11-05 |
| [未授权接口泄露阿里云 OSS AK/SK：oss2 验证、Bucket 枚举与生产报表 PII 取证](cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof.md) | verified | high | 2026-11-05 |
| [泄露 AK 缺少 SK：sts get-access-key-info 反查账号 ID，口令复用登录 AWS 控制台读 Secrets Manager 并连 RDS 取数](cloud-cloud-iam-access-key-info-account-id-password-reuse-console.md) | verified | high | 2026-11-13 |
| [泄露 AWS AK → Secrets Manager 取外部供应商口令 → CloudShell 凭据 → 借 trust policy 中可见的 ExternalId 扮演高权角色](cloud-cloud-iam-leaked-ak-secretsmanager-cloudshell-assume-role-external-id.md) | verified | high | 2026-11-13 |
| [泄露的华为云 AKSK 创建 IAM 子账户加入管理组接管控制台](huawei-obs-aksk-iam-console-takeover.md) | draft | high | 2026-11-08 |
| [腾讯云 AK/SK 经 tccli CAM 创建管理员子用户并登录控制台接管](cloud-cloud-iam-tencent-cam-subuser-console-takeover.md) | verified | high | 2026-11-12 |
| [腾讯云临时凭据权限枚举与 CVM 强制重置 root 密码](cloud-cloud-iam-tencent-temp-credential-cvm-password-reset.md) | verified | medium | 2026-11-05 |
| [阿里云临时凭证经 CF 工具列权与 OSS 搜刮后接管控制台：cf alibaba console 创建 RAM 后门用户](cloud-cloud-iam-aliyun-temp-credential-cf-console-takeover.md) | verified | high | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
