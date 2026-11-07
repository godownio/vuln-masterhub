---
id: cloud-object-storage-dangling-cname-bucket-takeover
title: 对象存储 Bucket 删除后 CNAME 悬空导致自定义域名接管
type: scenario
domain: cloud
path: cloud
technique: object-storage-dangling-cname-bucket-takeover
aliases:
- 对象存储 CNAME 接管
- Bucket 悬空接管
- NoSuchBucket 域名劫持
- 云存储子域接管
- dangling CNAME bucket takeover
tags:
- cloud
- object-storage
- oss
- cos
- s3
- cname
- subdomain-takeover
- phishing
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:27+08:00'
  notes: 已对照原文与图片09/11核对：删除Bucket未解绑自定义域名，DNS CNAME仍指向厂商Bucket端点，访问返回NoSuchBucket；图11阿里云删除Bucket提示自定义域名自动解绑并需确认CDN CNAME不再解析。卡内流程(dig确认CNAME→NoSuchBucket→同地域创建同名Bucket→上传验证文件)与原文一致，并说明AccessDenied不可接管。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

用户为 Bucket 绑定自定义域名后，在 DNS 配置了一条指向 Bucket 官方域名的 CNAME；若删除 Bucket 却未删除 CNAME，域名会持续指向不存在的 Bucket 并返回 `NoSuchBucket`；攻击者在同厂商、同地域创建同名 Bucket，即可接管该域名并托管钓鱼页面或恶意内容。

## 原理

- 对象存储的自定义域名通常通过 CNAME 指向 Bucket 的厂商域名（如 `static.test.com CNAME test.oss-cn-shanghai.aliyuncs.com`）。
- 删除 Bucket 时，DNS 记录不会自动删除；域名仍解析到厂商的 Bucket 端点，但该 Bucket 已不存在，访问返回 `NoSuchBucket`。
- Bucket 名称在同一厂商内全局唯一，但删除后名称会被释放（部分厂商有保留期）；攻击者若能在同地域创建同名 Bucket，就能接收该域名的流量。
- 接管后可上传任意静态内容（钓鱼页、恶意 JS/HTML、伪造下载），利用原域名的信任关系窃取凭据、分发恶意软件或做品牌钓鱼。
- 若原域名被用于 OAuth 回调、下载源、登录跳转，接管后危害更大；但对象存储本身通常不执行服务端脚本。

## 触发条件

- 目标域名 CNAME 指向对象存储 Bucket 端点，但对应 Bucket 已删除/不存在。
- 访问域名返回 `NoSuchBucket`（而非 `AccessDenied`）。
- Bucket 名称可被攻击者在同厂商、同地域重新创建（未被保留、未绑定其他账号）。
- 域名未被其他防护（WAF、证书固定、CAA 限制）阻断。

## 利用步骤

1. 收集目标使用的自定义域名/子域，检查 CNAME 是否指向 `*.oss-cn-*.aliyuncs.com`、`*.cos.*.myqcloud.com`、`*.s3.*.amazonaws.com` 等。
2. 访问该域名；若返回 `NoSuchBucket`/`The specified bucket does not exist`，说明 Bucket 不存在。
3. 用 `dig`/`nslookup` 确认 CNAME 目标与地域；记录原 Bucket 名称与地域。
4. 在攻击者账号下、同厂商同地域创建同名 Bucket；若名称已被占用/保留，接管失败。
5. 上传验证文件（如 `verify.txt`），访问自定义域名确认解析到攻击者 Bucket。
6. 根据授权范围评估影响：上传钓鱼页/恶意内容，或仅证明接管；不要对真实用户投放钓鱼。
7. 记录证据并报告，协助删除悬空 CNAME 或重新创建原 Bucket。

## PoC

DNS 检查：

```bash
dig static.test.com CNAME +short
# 预期：test.oss-cn-shanghai.aliyuncs.com.
curl -i https://static.test.com
# 预期：404 / NoSuchBucket
```

创建同名 Bucket（控制台或 CLI，示意）：

```bash
# 阿里云 OSS CLI 示例（需攻击者自己的凭证）
ossutil mb oss://test --region cn-shanghai
echo "takeover-proof" > verify.txt
ossutil cp verify.txt oss://test/verify.txt
curl https://static.test.com/verify.txt
# 预期返回 takeover-proof
```

## 变体与关联

- 变体：CNAME 指向已删除的 CDN 加速域名、负载均衡、其他云服务，也可能存在类似悬空接管。
- 变体：Bucket 名称有保留期/全局唯一限制时，攻击者可能无法重建；可尝试同区域/其他厂商的等价端点。
- 变体：接管后结合原域名的 Cookie 作用域、OAuth 回调、CSP 白名单扩大影响。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]（Bucket ACL 公共读/读写）。
- 关联：[[web-generic/subdomain-takeover]] 下的通用子域接管卡（如有）。
- 注意：`AccessDenied` 表示 Bucket 仍存在但不公开，不能接管；只有 `NoSuchBucket` 才是候选。

## 检测与防御

- 防御：删除 Bucket 前先删除/更新 DNS CNAME；定期审计指向对象存储/云服务的 CNAME，排查悬空记录。
- 防御：启用厂商的域名绑定校验（域名所有权验证）；为关键域名设置 CAA、监控证书透明度日志；删除后保留 Bucket 名称或使用不可预测名称。
- 检测：DNS 记录指向不存在的 Bucket；域名返回 `NoSuchBucket`；同名 Bucket 在异常账号下被创建；自定义域名内容突变/证书异常；访问日志出现异常上传。
- 响应：重新创建原 Bucket 并恢复内容，或删除悬空 CNAME；检查域名是否被用于钓鱼/OAuth 回调；通知用户与品牌团队。
