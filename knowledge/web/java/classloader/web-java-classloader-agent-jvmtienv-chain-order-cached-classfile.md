---
id: web-java-classloader-agent-jvmtienv-chain-order-cached-classfile
title: Java Agent 攻防：jvmtiEnv 链顺序与 _cached_class_file 缓存决定 redefine/retransform 的检测可见性与回滚
type: scenario
domain: web
path: web/java/classloader
technique: java-agent-jvmtienv-chain-order-cache-semantics
aliases:
- Java Agent 攻防博弈
- jvmtiEnv 链顺序
- 缓存字节码绕过检测
- retransform redefine 检测差异
- _cached_class_file
tags:
- java
- agent
- memshell
- jvmti
- instrumentation
- evasion
- detection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:40:38+08:00'
  notes: 已对照原文 12556 全文与 49 张图核对：类加载流程图（图01-04）、防护模式 redefine 654→685（图06/07）、retransform 仍 654（图07）、临时检测模式 retransform 检出 685（图08）、redefine 检出 732（图09）、缓存返回非 null 后被回滚且检测 654（图11/12）均与卡片描述一致；setHasRetransformableTransformers/普通 transformer 先执行等结论与原文一致。查重命中自身，其余仅与本篇其它四卡及既有 fileless-agent 无文件卡 related，非同链重复。JDK8 平台无产品版本，affected_versions 保持省略。未实测运行 PoC。
---

## 一句话结论

Agent 型内存马的检测结果由两点决定：攻击者与防御者 `JvmtiEnv` 节点在链上的先后顺序，以及目标类是否已有 `_cached_class_file` 缓存——防护 Agent 先于攻击者时，`redefineClasses` 的恶意字节码会被防御 transformer 看到，而攻击者后追加的 `canRetransform` transformer 在 `retransformClasses` 时最后执行，防御方只能知道类被重载却看不到修改后的字节码；防御方事后 `retransformClasses` 检测时，若类已有缓存则直接使用缓存字节码，既看不到攻击修改也可能把攻击修改回滚。

## 原理

- **两条 JVMTI 链与执行顺序**：Agent 加载时 JVM 创建 `JvmtiEnv` 节点挂在 `JvmtiEnvBase::_head_environment` 链表上；`addTransformer(canRetransform=false)` 走普通 transform 链，首次 `addTransformer(..., true)` 会通过 `setHasRetransformableTransformers` 在链尾追加一个 `retransformable` 节点。类加载/重定义时，普通 transformer 永远先于可重转换 transformer 执行；同一批内按添加顺序执行。
- **redefineClasses**：直接用攻击者传入的字节码替换类，路径不经过“缓存字节码”分支；在防护模式下，防御方的 transformer 会看到攻击后的字节码，因此可检测。
- **retransformClasses**：JVM 先取“初始字节码”——若 `InstanceKlass._cached_class_file` 有缓存则直接用缓存，否则根据当前类重新生成。攻击者先 `addTransformer(...,true)` 再 retransform 时，若其 transformer 添加在防御方之后（链尾），防御方 transformer 先执行并看到的是攻击前字节码，攻击者的修改在其后生效，防御方无法看到结果。
- **缓存的形成**：只有在某个 retransformable transformer 的 `transform` 返回非 `null` 时，JVM 才把该次字节码存入 `_cached_class_file`（classFileParser/jvmtiExport 逻辑）。因此防御方第一次检测时若自己也返回非 null，就制造了缓存。
- **防御方事后检测的两种结局**：类无缓存时，`retransformClasses` 生成的“初始字节码”正是攻击者 `redefineClasses` 后留在 InstanceKlass 中的恶意字节码，可发现；类有缓存时，使用缓存（通常为攻击前/上次转换结果），既看不到攻击修改，也可能让攻击者的 redefine 被回滚（类恢复缓存版本）。
- 结论：攻击方要隐蔽，需保证自己的 retransformable 节点在链尾；防御方要可靠检测，应在攻击前就处于“防护模式”或接受“有缓存时可能漏检+回滚”的语义。

## 触发条件

- 目标为 JDK8 系（文章基于 openjdk 8u121），攻击/防御双方都以 Java Agent 方式操作同一 JVM；
- 攻击者能加载 Agent 并调用 `addTransformer`/`retransformClasses`/`redefineClasses`；
- 防御方已加载（防护模式）或事后通过 Attach 加载检测 Agent；
- 目标类已被 `retransformClasses` 转换过（存在缓存）或未转换过，对应不同检测结果。

## 利用步骤

1. 攻击前先判断链上已有节点：用 `Instrumentation` 或内存解析确认防御方 transformer 与自身 transformer 的先后。
2. 若走隐蔽路线：`addTransformer(transformer, true)` 后 `retransformClasses(target)`，确保自身节点位于链尾；防御方只能感知“类被重新加载”。
3. 若走 redefine 路线：`redefineClasses` 会经过防御 transformer，应预期被检测。
4. 防御方检测：Attach 加载 Agent，`addTransformer` 检测器后 `retransformClasses(target)`；若返回的字节码长度/内容等于攻击前版本且类行为已恢复，说明命中了缓存回滚；若等于攻击后版本则发现篡改。

## PoC

测试三件套（原文 agentcrack）：app 内关键类 `T`、`javaagent-hack`（redefine/retransform）、`javaagent-monitor`（打印 `T` 字节码长度）。

```bash
# 防护模式启动，关键类 T 大小 654
java -javaagent:javaagent-monitor.jar -cp app.jar com.rzte.agentcrack.App
# 攻击者 redefine：防护方检测到 T 变为 685
java -jar javaagent-hack.jar <app_pid> redefine
# 攻击者 retransform：防护方仍打印 654（只看到重载，看不到修改）
java -jar javaagent-hack.jar <app_pid> retransform
```

临时检测模式下的缓存实验：防御方 `transform` 返回非 null 制造缓存后，攻击者 redefine 再检测，输出显示 `T` 仍为 654 且攻击修改被回滚。

## 变体与关联

- 变体：攻击者在检测后重新注入并守护（检测被回滚后再次在链尾注入），可让基于扫描的查杀失效。
- 变体：先卸载自身 transformer 再触发转换，使后续检测看不到 transform 链上的恶意实现。
- 关联：[[web-java-classloader-attach-api-jvmti-agent-memory-shell]]——标准 Attach + transformer + HttpServlet 内存马。
- 关联：[[defense-detection-arthas-agent-memshell-detect-remove]]——Arthas 查杀与缓存字节码细节。
- 关联：[[web-java-classloader-agent-jvmtienv-tail-move-evade-detection]]——利用链尾规则的主动规避实现。

## 检测与防御

- 防御：防护模式提前加载、监控 `addTransformer`/`retransformClasses`/`redefineClasses`；检测时同时比对 `_cached_class_file` 与当前 InstanceKlass 字节码，不能只看 transformer 返回值。
- 检测：关注非预期时间点的类重载（`classBeingRedefined != null`），即使拿不到修改后字节码，重载事件本身就是强信号。
- 攻击面提示：仅靠事后 retransform 检测存在“缓存导致漏检+回滚”的语义，需结合行为/内存扫描。
