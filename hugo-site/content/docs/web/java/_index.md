---
title: Java Web
weight: 1
---

# Java Web

## 这层是什么

Java 生态的表达式、反序列化、框架与组件漏洞。

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

- [Java 反序列化](deserialization/) —— 原生反序列化、gadget 链、触发点、绕过与利用。
- [表达式注入](expression/) —— SpEL、OGNL、MVEL、EL 等表达式注入。
- [Java 框架](framework/) —— Spring、Struts2、Shiro、Spring Boot 等框架漏洞。
- [Java 组件](component/) —— WebLogic、Tomcat、Confluence、Jenkins 等组件漏洞。
- [RMI](rmi/) —— RMI 注册表、DGC、动态类加载与利用。
- [类加载](classloader/) —— ClassLoader、字节码、内存马与加载机制。
- [命令执行与反弹 Shell](rce/) —— Runtime.exec/ProcessBuilder、反射进程创建与反弹 Shell。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [OA 下载 Servlet 在 finally 回调 doFollowupProcess，子类 file.delete() 导致下载即任意文件删除](web-java-oa-download-servlet-followup-delete-arbitrary-file/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
