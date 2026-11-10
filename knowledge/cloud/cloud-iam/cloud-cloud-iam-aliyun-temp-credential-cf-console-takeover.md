---
id: cloud-cloud-iam-aliyun-temp-credential-cf-console-takeover
title: 阿里云临时凭证经 CF 工具列权与 OSS 搜刮后接管控制台：cf alibaba console 创建 RAM 后门用户
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: aliyun-temp-credential-cf-console-takeover
aliases:
- CF 接管阿里云控制台
- cf alibaba console
- crossfire RAM 后门用户
- 阿里云临时凭证利用
- 阿里云 AK 列权与 OSS 搜刮
tags:
- cloud
- aliyun
- cloud-iam
- credential
- oss
- ram
- persistence
- cf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:42:34+08:00'
  notes: 已对照原文核对：cf config/perm/ls/console/console cancel 命令、AdministratorAccess、crossfire 后门用户与 signin.aliyun.com 登录均与截图一致；未验证点：OSS 配置文件内 AK/SK 与 AdministratorAccess 的归属在原文表述有歧义，卡片按临时凭证权限理解，OSS 桶名/配置内容打码
---

## 一句话结论

拿到阿里云实例 RAM 角色的临时 AK/SK/SecurityToken 后，可用 CF（Cloud Exploitation Framework）的 alibaba 模块快速列权并列举 OSS/ECS/RDS；若凭证带 `AdministratorAccess`，还能从 OSS 桶里的配置文件再收集长期 AK/SK，并用 `cf alibaba console` 直接创建一个 `crossfire` RAM 后门用户登录阿里云控制台——把“会过期的临时凭证”升级为“可长期登录的控制台权限”。

## 原理

- **临时凭证就是 API 身份**：阿里云元数据返回的 `AccessKeyId`/`AccessKeySecret`/`SecurityToken` 三元组与 RAM 角色权限等价，可在 `Expiration` 前调用任意阿里云 OpenAPI；CF 等工具只是把常用查询封装成命令。
- **列权与枚举**：`cf alibaba perm` 调用 RAM 接口列出当前凭证挂载的策略（如系统策略 `AdministratorAccess`），`cf alibaba ls` 列举 OSS 桶、ECS、RDS 等资源；权限为 AdministratorAccess 时几乎不受限。
- **OSS 是二次凭据库**：对象存储常存放网站备份、部署配置、`.env`、数据库与云服务配置；桶内配置文件里常有另一组长期 AK/SK 或其他云服务凭据，可继续横向，且不依赖原始临时凭证的过期时间。
- **控制台接管为什么成立**：`cf alibaba console` 不是“破解登录”，而是用当前高权限凭证调用 RAM 管理 API 新建一个 RAM 用户（工具默认命名 `crossfire`），为其开启控制台登录并生成用户名/密码/登录地址。创建 RAM 用户、设置登录配置都是合法 API，只要当前凭证拥有 RAM 管理权限；生成的登录口令是长期凭证，即使 STS 过期仍可登录，因此天然成为后门。`cf alibaba console cancel` 用于删除该后门用户。
- **告警边界**：创建 RAM 用户通常会触发短信/安全告警，创建云函数或恶意镜像也可能被拦截；权限足够时攻击者可在控制台安全中心关闭监控，这正是该链危险之处。

## 触发条件

- 已获得有效的阿里云凭证（本链常见来源是元数据临时凭证，也适用于泄露的长期 AK/SK），且权限包含 OSS/ECS/RAM 管理。
- 攻击者可访问阿里云公网 API（`signin.aliyun.com`、`ram.aliyuncs.com`、OSS/ECS 端点）。
- 目标未禁用 RAM 用户创建/控制台登录，或未对异常登录做实时阻断。
- 临时凭证在有效期内（过期需重新从元数据或其他入口获取）。

## 利用步骤

1. 配置凭证：`./cf config` 填入 AccessKeyId、AccessKeySecret、SecurityToken（如有）。
2. 列权：`./cf alibaba perm`，确认策略是否含 `AdministratorAccess` 或 OSS/ECS/RAM 写权限。
3. 列举资源：`./cf alibaba ls`，查看 OSS 桶、ECS、RDS 清单；优先关注体积大、名称像备份/日志/配置的桶。
4. 翻 OSS 找配置：枚举并下载桶内配置文件（备份包、`.env`、`config.*`、部署脚本），收集其中新的 AK/SK 与其他凭据，扩大控制面。
5. 接管控制台：`./cf alibaba console`，工具创建 `crossfire` RAM 用户并输出用户名、密码与 `https://signin.aliyun.com` 登录地址；用该账号登录控制台查看资源。
6. 按需维持/清理：新建 RAM 用户与 AccessKey；原文还提到可创建云函数后门、制作带后门的自定义镜像（未逐一演示）；清理时执行 `./cf alibaba console cancel` 删除 crossfire 用户。

## PoC

```bash
# 1) 配置元数据/泄露得到的阿里云临时凭证
./cf config

# 2) 查看当前凭证策略（示例输出含 AdministratorAccess）
./cf alibaba perm

# 3) 列举 OSS/ECS/RDS 资源
./cf alibaba ls

# 4) 创建 RAM 后门用户并获取控制台登录信息
./cf alibaba console

# 5) 清理后门用户（授权测试收尾）
./cf alibaba console cancel
```

说明：`perm`/`ls`/`console` 的输出与截图一致；`console` 创建的用户名默认为 `crossfire`，登录地址为 `https://signin.aliyun.com`。权限不足时 `perm` 只显示部分策略，`ls` 可能为空——此时需先找更高权限凭证。

## 变体与关联

- 变体（凭据来源）：实例元数据临时凭证（见关联卡）、前端 JS/配置中心/Nacos/Actuator 泄露的长期 AK/SK、OSS 桶内二次泄露。
- 变体（持久化）：新建 RAM 用户 + 长期 AccessKey；云函数后门；带后门的自定义镜像（诱导目标用镜像创建 ECS 时触发）；控制台关闭安全中心监控规避告警。
- 关联：[[cloud-metadata-ueditor-catchimage-aliyun-ram-credential]]（元数据凭证获取入口）、[[cloud-cloud-iam-frontend-js-alibaba-ak-sk-cloud-takeover]]（前端 JS 泄露 AK 的 OSS/ECS 接管）、[[cloud-cloud-iam-nacos-config-aliyun-ak-sk-oss-takeover]]（配置中心泄露 AK 接管 OSS）、[[cloud-cloud-iam-aws-backdoor-user-key-persistence]]（AWS 对应的后门用户持久化思路）。

## 检测与防御

- 检测：云审计中非业务 IP/时间调用 `ram:CreateUser`、`ram:CreateLoginProfile`、`ram:CreateAccessKey`；`signin.aliyun.com` 出现新 RAM 用户登录；OSS 出现批量 `ListObjects`/`GetObject`；临时凭证在元数据以外的来源被使用。
- 防御：元数据启用仅加固模式并阻断 SSRF；RAM 角色最小权限，禁止业务角色挂 `AdministratorAccess`；为 RAM 管理 API 设置 MFA/审批与告警；定期审计 RAM 用户、登录配置与 AccessKey；OSS 桶禁止存放明文长期 AK/SK，开启加密与访问日志。
- 处置：发现 crossfire 等异常 RAM 用户立即删除并轮换相关 AK；排查同凭证创建过的云函数、镜像与 ECS 实例。
