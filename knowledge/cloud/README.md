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

- [Kubernetes](k8s/README.md) —— 集群、RBAC、Admission、逃逸与供应链。
- [容器](container/README.md) —— Docker、runc、镜像与运行时逃逸。
- [Serverless](serverless/README.md) —— 函数计算、事件注入与权限。
- [CI/CD](ci-cd/README.md) —— 流水线、凭据、供应链与投毒。
- [云 IAM](cloud-iam/README.md) —— 权限提升、角色链、跨账号与策略缺陷。
- [云元数据](metadata/README.md) —— 元数据服务、SSRF 与临时凭证。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AWS EFS 挂载目标安全组全开：用 describe-* 拿到 NFS IP，在受控 EC2 上直接 mount 共享文件系统](cloud-efs-mount-target-open-security-group-nfs-mount.md) | verified | high | 2026-11-08 |
| [DynamoDB 无鉴权：list-tables/scan 明文导出用户口令表，凭据直登 SSH 横向移动](cloud-dynamodb-unauth-scan-credential-ssh-lateral.md) | verified | high | 2026-11-08 |
| [EC2 UserData 持久化：写入 cloud-init 的 scripts-user, always 让脚本每次重启都以 root 执行（后门反弹/公钥/任意命令）](cloud-ec2-userdata-cloud-init-always-persistence.md) | verified | high | 2026-11-08 |
| [EC2 后门入口开路：新建安全组 + authorize-security-group-ingress 0.0.0.0/0，再用 modify-instance-attribute --groups 整体替换实例安全组](cloud-ec2-security-group-full-open-instance-replace.md) | verified | high | 2026-11-08 |
| [Prometheus 未授权管理 API：status/flags 探测后调用 tsdb snapshot/delete_series 快照或删除监控数据](cloud-prometheus-unauth-admin-api-tsdb-snapshot-delete.md) | verified | medium | 2026-11-13 |
| [S3 WRITE_ACP 权限滥用：改写对象/桶 ACL 把 FULL_CONTROL 授予自己实现接管](cloud-s3-write-acp-acl-takeover.md) | verified | medium | 2026-11-12 |
| [S3 兼容端点无鉴权：伪造凭证 awscli 匿名列桶，向映射 Web 根目录的桶上传 PHP 获得 RCE](cloud-s3-unauth-endpoint-php-upload-rce.md) | verified | high | 2026-11-08 |
| [S3 存储桶名称释放后劫持软件更新源与供应链](cloud-s3-released-bucket-name-update-channel-hijack.md) | verified | medium | 2026-11-05 |
| [S3 版本控制下匿名 list-object-versions：下载旧版 auth.js 恢复已删除凭据，并用旧版机密 xlsx 取数](cloud-s3-versioning-hidden-old-object-credential-recovery.md) | verified | high | 2026-11-13 |
| [公共 RDS 快照还原到自建 VPC + 改主密码 + psql 连接读取业务/flag 数据](cloud-public-rds-snapshot-restore-master-password-data-loot.md) | verified | high | 2026-11-08 |
| [公开 EBS 快照（createVolumePermission=all）→ 创建卷挂载 EC2 → 文件系统挖硬编码 AK/SK](cloud-public-ebs-snapshot-volume-mount-credential-loot.md) | verified | high | 2026-11-08 |
| [公网可访问 RDS + 弱口令：nmap mysql-brute 命中 dbuser:123 直连数据库拖库](cloud-public-rds-open-weak-password-flag.md) | verified | high | 2026-11-13 |
| [华为云 OBS 桶 ACL 对 Everyone 授予 WRITE_ACP：匿名 PUT /?acl 改成 FULL_CONTROL 后接管读权限](cloud-obs-bucket-acl-write-acp-anonymous-takeover.md) | verified | high | 2026-11-13 |
| [华为云 OBS 桶枚举：NoSuchBucket / AccessDenied / ListBucketResult 三态差分定位存在桶](cloud-obs-bucket-existence-enumeration-differential.md) | verified | high | 2026-11-13 |
| [华为云 OBS 桶策略与桶 ACL 冲突：ListBucket 关闭但 ACL 允许匿名仍可列对象](cloud-obs-bucket-policy-acl-conflict-anonymous-list.md) | verified | high | 2026-11-13 |
| [华为云 OBS 防盗链 Referer 白名单绕过：请求头补白名单 Referer 即可下载受保护对象](cloud-obs-hotlink-referer-whitelist-bypass.md) | verified | high | 2026-11-13 |
| [对象存储 Bucket ACL 配置错误：公共读 ListObject 目录遍历与公共读写 PUT 上传](cloud-object-storage-bucket-acl-misconfig.md) | verified | high | 2026-11-05 |
| [对象存储 Bucket 删除后 CNAME 悬空导致自定义域名接管](cloud-object-storage-dangling-cname-bucket-takeover.md) | verified | high | 2026-11-05 |
| [对象存储公共写 + response-content-type 覆盖：上传 HTML 后强制按 text/html 解析触发存储型 XSS](cloud-object-storage-response-content-type-xss.md) | verified | high | 2026-11-05 |
| [对象存储可变元数据跨身份隐蔽信道：Object Tagging 与未完成 Multipart ListParts 分片长度编码](cloud-object-storage-metadata-covert-channel-tagging-multipart.md) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
