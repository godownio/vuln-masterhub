---
title: 云安全
weight: 1
---

# 云安全

## 这层是什么

云原生、容器、Kubernetes、CI/CD 与 IAM。

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

- [Kubernetes](k8s/) —— 集群、RBAC、Admission、逃逸与供应链。
- [容器](container/) —— Docker、runc、镜像与运行时逃逸。
- [Serverless](serverless/) —— 函数计算、事件注入与权限。
- [CI/CD](ci-cd/) —— 流水线、凭据、供应链与投毒。
- [云 IAM](cloud-iam/) —— 权限提升、角色链、跨账号与策略缺陷。
- [云元数据](metadata/) —— 元数据服务、SSRF 与临时凭证。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AWS EFS 挂载目标安全组全开：用 describe-* 拿到 NFS IP，在受控 EC2 上直接 mount 共享文件系统](cloud-efs-mount-target-open-security-group-nfs-mount/) | verified | high | 2026-11-08 |
| [DynamoDB 无鉴权：list-tables/scan 明文导出用户口令表，凭据直登 SSH 横向移动](cloud-dynamodb-unauth-scan-credential-ssh-lateral/) | verified | high | 2026-11-08 |
| [EC2 UserData 持久化：写入 cloud-init 的 scripts-user, always 让脚本每次重启都以 root 执行（后门反弹/公钥/任意命令）](cloud-ec2-userdata-cloud-init-always-persistence/) | verified | high | 2026-11-08 |
| [EC2 后门入口开路：新建安全组 + authorize-security-group-ingress 0.0.0.0/0，再用 modify-instance-attribute --groups 整体替换实例安全组](cloud-ec2-security-group-full-open-instance-replace/) | verified | high | 2026-11-08 |
| [S3 兼容端点无鉴权：伪造凭证 awscli 匿名列桶，向映射 Web 根目录的桶上传 PHP 获得 RCE](cloud-s3-unauth-endpoint-php-upload-rce/) | verified | high | 2026-11-08 |
| [S3 存储桶名称释放后劫持软件更新源与供应链](cloud-s3-released-bucket-name-update-channel-hijack/) | verified | medium | 2026-11-05 |
| [公共 RDS 快照还原到自建 VPC + 改主密码 + psql 连接读取业务/flag 数据](cloud-public-rds-snapshot-restore-master-password-data-loot/) | verified | high | 2026-11-08 |
| [公开 EBS 快照（createVolumePermission=all）→ 创建卷挂载 EC2 → 文件系统挖硬编码 AK/SK](cloud-public-ebs-snapshot-volume-mount-credential-loot/) | verified | high | 2026-11-08 |
| [对象存储 Bucket ACL 配置错误：公共读 ListObject 目录遍历与公共读写 PUT 上传](cloud-object-storage-bucket-acl-misconfig/) | verified | high | 2026-11-05 |
| [对象存储 Bucket 删除后 CNAME 悬空导致自定义域名接管](cloud-object-storage-dangling-cname-bucket-takeover/) | verified | high | 2026-11-05 |
| [对象存储公共写 + response-content-type 覆盖：上传 HTML 后强制按 text/html 解析触发存储型 XSS](cloud-object-storage-response-content-type-xss/) | verified | high | 2026-11-05 |
| [对象存储可变元数据跨身份隐蔽信道：Object Tagging 与未完成 Multipart ListParts 分片长度编码](cloud-object-storage-metadata-covert-channel-tagging-multipart/) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
