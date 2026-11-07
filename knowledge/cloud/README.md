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
| [S3 存储桶名称释放后劫持软件更新源与供应链](cloud-s3-released-bucket-name-update-channel-hijack.md) | verified | medium | 2026-11-05 |
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
