---
title: HTTP 请求走私
weight: 1
---

# HTTP 请求走私

## 这层是什么

CL/TE、TE/TE、HTTP/2 降级与利用。

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
| [Content-Encoding 压缩请求体：WAF 不解码而后端解码导致请求体检查绕过](web-generic-http-smuggling-content-encoding-request-body-waf-bypass/) | verified | high | 2026-11-05 |
| [eBPF tc ingress 逐包关键字过滤绕过：TCP 分段打散 "flag" + TCP 头 0x25 随机丢包下 Range 小步重试](web-generic-http-smuggling-ebpf-tc-header-scan-percent-random-drop/) | verified | medium | 2026-11-06 |
| [eBPF TC 无状态防火墙绕过：TCP 分段与 HTTP Range 双向规避](web-generic-http-smuggling-ebpf-tc-stateless-keyword-bypass/) | verified | high | 2026-11-05 |
| [Varnish HTTP/1 管线残留：CL body 后的第二请求被复用连接转发（CVE-2022-23959 补丁路径正交）](web-generic-http-smuggling-varnish-pipeline-cl-residual/) | verified | medium | 2026-11-05 |
| [多成员 gzip 请求体解压范围错位：网关校验首 member、后端执行全部 member](web-generic-http-smuggling-gzip-multi-member-decompression-differential/) | verified | high | 2026-11-04 |
| [未知 Transfer-Encoding 解析差异走私：代理按 chunked 截断、Flask 按 Content-Length 读全 body 绕过 WAF](web-generic-http-smuggling-unknown-te-cl-differential/) | verified | high | 2026-11-06 |
| [空 Content-Length + TE chunked 解析差异：前置代理拦截 /admin，走私第二个 GET 到后端渲染路由](web-generic-http-smuggling-empty-cl-chunked-admin-bypass/) | verified | medium | 2026-11-06 |
| [连接状态攻击绕过 Host 校验：同一 keep-alive 连接先合法请求再打内网](web-generic-http-smuggling-host-connection-state-bypass/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
