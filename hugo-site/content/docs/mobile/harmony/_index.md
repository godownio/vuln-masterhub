---
title: HarmonyOS
weight: 1
---

# HarmonyOS

## 这层是什么

HAP/APP/ABC、方舟运行时与安全机制。

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
| [HAP 静态提取硬编码管理员哈希：SHA256 token 派生 + SM4-ECB 解密 flag](mobile-harmony-hap-hardcoded-admin-token-sm4-flag/) | verified | high | 2026-11-06 |
| [HarmonyOS ArkTS + NAPI 逆向：混淆常量恢复、密码哈希拼接与 SM4/VM 解密 flag](mobile-harmony-arkts-napi-obfuscated-constants-sm4-vm-flag/) | verified | high | 2026-11-06 |
| [HarmonyOS HAP 的 ABC 字节码反编译后用固定 XOR key 还原硬编码接口与密钥](mobile-harmony-hap-abc-xor-hardcoded-secrets/) | verified | high | 2026-11-08 |
| [HarmonyOS HAP 逆向流程：sourceMaps 泄露源码树 + modules.abc 反编译 + ArkTS 字节码阅读](mobile-harmony-hap-abc-reverse-sourcemaps-workflow/) | verified | high | 2026-11-06 |
| [HarmonyOS HAP 逆向：ArkTS 派生 seed + native S-box/128 位仿射变换，Unicorn 黑盒 + GF(2) 消元反解 UUID](mobile-harmony-hap-arkts-native-sbox-affine-unicorn/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
