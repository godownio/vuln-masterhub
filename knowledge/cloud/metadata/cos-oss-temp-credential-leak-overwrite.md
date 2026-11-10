---
id: cos-oss-temp-credential-leak-overwrite
title: 上传接口响应泄露云存储临时凭证实现任意文件上传与桶内覆盖
type: scenario
domain: cloud
path: cloud/metadata
technique: STS 临时凭证泄露滥用
aliases:
- STS token 泄露
- COS/OSS 任意上传
tags:
- cloud
- oss
- cos
- sts
- credential-leak
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-20
  verified_at: '2026-11-08T12:55:13+08:00'
  notes: 已对照原文核对：上传/导入接口响应泄露 bucket/tmp_secret_key/tmp_token(截图证实 myqcloud 桶与临时凭证三元组)、qcloud_cos CosConfig+put_object 脚本与根目录上传 a.txt 证据齐全；泄露与任意上传证据充分，桶内覆盖为原文明示的可行延伸(原文截图上传成功)；dedup 候选(未授权覆盖/STS policy 注入/前端JS AK泄露)均为不同链路；未验证点：覆盖既有对象的完整前后对比截图原文未展示
---

# 上传接口响应泄露云存储临时凭证实现任意文件上传与桶内覆盖

## 一句话结论

前端直传云存储（腾讯云 COS/阿里云 OSS）的接口在 prepare/签名响应包中返回 `bucket`、`tmp_secret_key`、`tmp_secret_id`、`tmp_token`（或 secret_id/secret_key）等临时凭证时，攻击者可用官方 SDK（qcloud_cos/boto3）直接调用 put_object 向桶内任意 Key（含网站根路径与其他站点共用目录）写文件、覆盖现有对象，实现静态资源投毒乃至接管关键文件。

## 原理

对象存储直传架构要求服务端下发热度签名或 STS 临时凭证；若后端把整套凭证无差别返回给客户端（且未做路径/后缀/前缀条件约束 policy），持有者即拥有与签名逻辑等价的写权限。SDK 以 secret_id+secret_key+token 组合直接签名请求，绕过前端所有校验。桶若同时服务多个站点/环境（共用静态资源桶），跨站点覆盖成为可能。

## 触发条件

- 抓包在请求/响应中可见 bucket 名与临时密钥三元组（key/token/secret）；
- 凭证未绑定上传前缀、Content-Type 白名单或 Key 前缀策略；
- 凭证在有效期内（STS 通常几十分钟）。

## 利用步骤

1. 上传/导入功能抓包，识别响应中的 `bucket/tmp_secret_key/tmp_token`（或 OSSAccessKeyId/policy/signature）。
2. 用官方 SDK 构造 CosConfig(Region, SecretId, SecretKey, Token) 客户端。
3. `put_object(Bucket=<桶名>, Key='a.txt', Body='test')` 验证任意上传。
4. 用桶内已知的业务路径 Key（如 `assets/up/.../x.png` 或网站根路径文件）重新上传覆盖。
5. 访问原 URL 验证内容被替换。

## PoC

无 PoC（原文含完整 qcloud_cos 脚本：CosConfig→CosS3Client→put_object，验证可向网站根目录上传并覆盖指定路径文件）。

## 变体与关联

- 变体：阿里云 OSS 前端 JS 硬编码 AK/SK（JS 里直接找 AK 与 AS）；响应泄露 policy+signature 时按 policy 约束构造；子账号权限过大时接管整个桶（列举/删除）。
- 关联：上传路径参数穿越（同为落盘位置失控，云上是 Key 任意）；Content-Type 混淆（覆盖后对象以可控 MIME 提供，叠加 XSS）。

## 检测与防御

- 检测：审计前端代码与接口响应中出现 secretKey/token 字段；COS/OSS 访问日志中出现非业务来源的 PutObject 与异常 Key。
- 防御：STS 凭证绑定 policy 限定 Key 前缀、Content-Type 与有效期；签名服务端化；静态桶与业务桶分离并开启版本控制/防误删；泄露凭证即时轮换。
