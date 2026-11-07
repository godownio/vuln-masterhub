---
id: code-analysis-dynamic-fuzzing-android-ebpf-intent-aware
title: 强加固 Android 应用的 Intent-aware 灰盒 fuzzer：eBPF 对象布局恢复 + Key-Value 反馈 + 选择性覆盖
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: android-ebpf-intent-aware-fuzzing
aliases:
- AHA-Fuzz
- Intent-aware fuzzer
- eBPF 对象布局恢复
- Key-Value Feedback
- 选择性覆盖
- 加固 App 模糊测试
tags:
- android
- fuzzing
- ebpf
- intent
- object-layout
- coverage-guided
- hardened-app
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V129
  verified_at: '2026-11-06T04:31:33+08:00'
  notes: 已对照原文及8张图核对：eBPF 对象布局恢复、Key-Value 反馈（String.equals/contains/数值比较常量）、选择性覆盖（dex_method_index/测量窗口）、AlarmManager/JobScheduler 时间重写、轻量污点 source→sink 均与原文一致；原文为论文原型、无 PoC，卡内已标注；Android 13 仅为实验环境，未设 affected_versions；关联卡 tools-frida-hook 不存在（卡内已注“如存在”）；PoC 未执行。
---

## 一句话结论

面对混淆/加壳/反调试的强加固 Android 应用，可在不改 APK、不改系统镜像的前提下，用 eBPF 在内核侧观测 ART/框架中 Intent、Bundle、IntentFilter 等对象的真实内存布局，恢复 action 与 extras 键值生成语义正确的 Intent 种子；再用比较语句的 Key-Value 反馈、Intent 窗口内的选择性覆盖、调度时间重写与轻量污点检测，把灰盒 fuzzing 从“随机 Intent”提升为能触发真实恶意逻辑的定向搜索。

## 原理

- **eBPF 旁观**：eBPF 可在内核函数入口/返回挂载小程序，低开销读取内核/用户空间状态；在 ART 与框架层与 Intent 相关的构造/访问点装 probe，多次观测后聚类推断 Java 对象的字段偏移与类型。
- **对象布局恢复**：相比 hook `putExtra`/`get*Extra`，从内存布局直接抽取 `action`、`extras` 的 key-value、`IntentFilter` 的 action/category，更能抵抗 wrapper、混淆与序列化差异。
- **有效 Intent 生成**：只用当前应用中真实注册/使用过的 action 与 extras 键生成种子，保证 Intent 语义正确，避免大量无效输入。
- **Key-Value 反馈**：监控 `String.equals`/`contains`、数值比较等指令；当比较一侧来自 Intent extras 时，把另一侧的常量（如 `"3gpp"`、`"LEAK"`）记录为该 key 的候选触发值，变异时注入，显著提高命中特定分支的概率。
- **选择性覆盖**：发送 Intent 前通知 eBPF 进入测量窗口，在 ART AOT/解释器入口按 `dex_method_index` 记录方法级覆盖；idle/超时后关闭窗口，使反馈只反映该 Intent 驱动的执行路径，避免 GUI/后台噪声。
- **调度时间重写**：hook `AlarmManager`、`JobScheduler` 等调度 API，把目标触发时间改为“当前时间 + 小偏移”，快速触发原本需要数天的延迟行为。
- **轻量污点**：监控敏感数据 API（设备 ID、网络能力）与泄露出口（日志、网络），建立 source→sink 模式，发现潜在信息泄露。

## 触发条件

- 目标为强加固 Android 应用（混淆/加壳/反调试/反模拟器），传统静态分析与重打包插桩失效。
- 测试环境为 root 的 ARM64 模拟器/设备（如 Android 13），内核支持 eBPF/BCC。
- 应用通过 Intent/组件通信触发核心逻辑，且存在延迟调度或信息泄露路径。
- 可接受不修改 APK/系统镜像的运行时观测方式。

## 利用步骤

1. 在 ART/框架的 Intent、Bundle、IntentFilter、ArrayList 构造/访问点部署 eBPF probe，采集对象地址、字段访问与调用事件。
2. 用户态按地址区间与字段偏移聚类，恢复对象布局；解析出 action、extras key-value、IntentFilter 信息。
3. 用真实 action/extras 生成 Intent 种子；对每个种子发送前开启覆盖测量窗口，结束后收集方法级覆盖。
4. 监控比较指令，收集与 extras 比较的常量，作为 key 的候选值注入变异。
5. hook 调度 API 重写触发时间；对敏感 API→日志/网络建立 source→sink 污点规则。
6. 以“选择性覆盖 + key-value 反馈 + 崩溃/泄露”为反馈调度种子，迭代 fuzz。

## PoC

```text
无 PoC（论文原型 AHA-Fuzz，文章给出架构与实验数据，未给出可直接运行的探针/脚本）。
关键观测点：Intent/Bundle/IntentFilter/ArrayList 构造与访问、String.equals/contains、数值比较、AlarmManager/JobScheduler、敏感数据 API 与日志/网络出口。
```

## 变体与关联

- 无 eBPF 环境时，可用 Frida hook 替代部分对象布局与比较反馈，但更易被反调试/反 hook 检测。
- 静态 Intent fuzzing（MATE/ICCBot/IntentFuzzer）在加固场景下易失效，可作为基线对比。
- 关联：[[mobile-android-anti-detection-root-emulator-proxy]]（反检测/代理对抗）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固与脱壳）、[[tools-frida-hook]]（如存在）。

## 检测与防御

- 应用侧：检测 eBPF probe/内核 tracing、root/模拟器、调试器与 hook 框架；对 Intent extras 做严格校验，减少可被 fuzz 的分支。
- 平台侧：限制 eBPF 权限（`kernel.unprivileged_bpf_disabled`）、审计 bpf syscall 与 perf_event_open。
- 检测：短时间内大量 Intent/组件调用、异常 extras 键值、调度 API 被频繁改写、敏感 API 到日志/网络的异常流动。
