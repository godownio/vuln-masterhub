---
id: code-analysis-sast-taie-log4shell-taint-detection
title: Tai-e 静态污点分析检测 Log4Shell：日志入口 call source + InitialContext/JndiManager lookup sink + StringBuilder 等 transfer 补齐
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-log4shell-taint-detection
tags:
- taie
- java
- sast
- taint-analysis
- log4shell
- log4j2
- jndi
- ldap
- pointer-analysis
- code-audit
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V617
  verified_at: '2026-11-12T20:57:29+08:00'
  notes: 已对照原文及4张截图核对：截图01 dnslog 回显 9710ck.dnslog.cn，截图02 五种污点转移示意，截图03 IDEA 运行配置 pascal.taie.Main + --options-file=java-benchmarks/log4j/2.14.0/options.yml，截图04 污点流图；卡片所述 InitialContext.lookup 为配置 sink、实际命中 JndiManager.lookup 与原文 tai-e.log 输出一致，StringBuilder append/toString transfer 签名与原文一致，33 层与 Tai-e 0.5.1 均出自原文。log4j-web 2.14.0 为被检测目标版本而非受影响区间，故不设 affected_versions。dedup 候选 toolchain/MyBatis/Servlet/entrypoint/Symphony 均 related 不同链；dup-scan 无涉及本卡 pair。未在本地实际运行 Tai-e 验证。
url: /docs/code-analysis/static/sast/code-analysis-sast-taie-log4shell-taint-detection/
draft: false
kb_aliases:
- Tai-e 检测 Log4Shell
- log4j 污点分析配置
- JNDI lookup sink
- StringBuilder transfer 污点转移
- JndiManager.lookup taint flow
---

## 一句话结论

用 Tai-e 污点分析静态检测 Log4Shell，核心是把污点入口配成 `kind: call` 的 source（演示为 `getInput()` 的返回值，实战对应 `request.getParameter` 等外部输入），把 JNDI 查找点 `<javax.naming.InitialContext: java.lang.Object lookup(java.lang.String)>` 的 `index: 0` 配成 sink（log4j2 内部实际命中的是 `JndiManager.lookup` 的同位点），再用 `transfers` 为 `StringBuilder.append/toString` 等方法补上污点形态变换的指针流向边，即可跨 33 层调用与反射 API 报出从日志入口字符串到 JNDI lookup 的 TaintFlow。

## 原理

- **污点即对象**：Tai-e 把污点建模成对象，挂在指针分析（PTA）的指向关系上传播，别名关系（同一个对象被多个变量指向）自然被覆盖；反射调用由 Tai-e 的静态反射分析补充调用边，避免数据流在反射处断开。source 在调用点生成"污染对象"，sink 在方法调用参数处匹配污染对象，命中即输出 TaintFlow。
- **Log4Shell 链为什么适合污点分析**：`logger.error(str)` 会把字符串交给 Lookup 机制解析 `${...}`，其中 `${jndi:ldap://...}` 触发 JNDI 查找，最终走到 `InitialContext.lookup(name)`（log4j2 在 `JndiManager.lookup` 中包装该调用），进而向攻击者控制的 LDAP/RMI 服务器发起请求。漏洞本质是"外部字符串直达 JNDI 查找"，正是 source→sink 的注入模式。
- **source 分类**：`kind: call` 在方法被调用的 call site 为返回值生成污点对象，最常用（`request.getParameter(str)`、`getInputStream()` 等封装方法）；`kind: param` 为没有显式调用点的入口方法参数造污点；`kind: field` 在字段被读取（`v = o.f`）时造污点。可选 `type` 用于指定实际对象类型——当方法声明返回 X、实际返回子类 Y 时，污点对象类型要对齐 `new Y()`。
- **sink 匹配**：只按方法签名 + 参数下标（或 `base`）匹配调用点变量；`new File(name)` 类构造器也可作 sink（如 index 0）。
- **为什么需要 transfers**：PTA 只处理 New/Assign/Store/Load/Call 五类语句的指向传播，方法调用内部的数据搬运（如 `StringBuilder.append(taint)` 把数据复制进新缓冲区、`toString()` 再取出）不会产生新的指向关系，污点会断。transfer 配置显式告诉 Tai-e 方法调用中 base/result/参数之间的污点流向，向指针流向图（PFG）补边，从而把 `String --> StringBuilder --> String` 串起来。转移形式共五种：base→result、arg→base、arg→result、base→arg、arg→arg。
- **链路长度与形态变换**：Log4Shell 的 log4j2 内部调用链跨越约 33 层方法，污点多次变换形态（String、Message、StringBuilder 缓冲等），并涉及反射 API；source/sink 配对后，足够的 transfer 与反射分析决定能否端到端报出。

## 触发条件

- 目标 Java 应用依赖存在 JNDI Lookup 的 log4j2（原文测试 `log4j-web 2.14.0`），且存在从外部可控字符串到 `logger.error/info/...` 的可达路径；
- 本地可运行 Tai-e（原文 0.5.1，主类 `pascal.taie.Main`）与官方 java-benchmarks，具备 log4j 的 jar 作为分析类路径；
- 能编写 taint-config（sources/sinks/transfers），并接受静态结果仍需人工核验；
- 若为 JavaWeb 应用，入口方法不是 main 时还需额外补入口点插件。

## 利用步骤

1. **构造可验证的测试项目**：Maven 项目引入 `log4j-web 2.14.0`，写 `Main`：`String poc = getInput(); logger.error(poc);`，`getInput()` 返回 `${jndi:ldap://<dnslog 子域>}`；运行程序，在 dnslog 平台看到 DNS 记录即确认 payload 可触发（只观察 DNS，不外连真实恶意服务）。
2. **配置 source**：`- {kind: call, method: "<Main: java.lang.String getInput()>", index: result}`；实战中替换为真实外部输入方法（Servlet `getParameter`、请求体读取等）。
3. **配置 sink**：`- { method: "<javax.naming.InitialContext: java.lang.Object lookup(java.lang.String)>", index: 0 }`；log4j2 内部包装点 `org.apache.logging.log4j.core.net.JndiManager.lookup(java.lang.String)` 同样可作 sink（原文实际命中的就是它）。
4. **配置 transfers**：至少补 `StringBuilder.append(String)` 的 `from: 0, to: base` 与 `StringBuilder.toString()` 的 `from: base, to: result`；按应用实际使用的字符串拼接/格式化方法继续补，直到 source 能连到 sink。
5. **运行 Tai-e**：IDEA 中主类 `pascal.taie.Main`、程序参数 `--options-file=java-benchmarks/log4j/2.14.0/options.yml`（或命令行 `java -jar tai-e-all.jar --options-file ...`）；常用程序选项 `-cp`（仅主类引用闭包）、`-acp`（全部加入 closed world）、`-m`、`--input-classes`、`-java`、`-pp`、`-ap`；分析选项 `-a "pta=cs:2-type;time-limit:60;"`；开发期可加 `-wc` 世界缓存、`--output-dir` 指定输出。
6. **验证结果**：查看 `output/tai-e.log` 中 `Detected N taint flow(s)` 与 TaintFlow 的 source/sink 语句位置（示例命中 `<Server: void main(java.lang.String[])>[12@L8] getInput()/result -> JndiManager.lookup(...)/0`）；用 `dot -Tsvg -o taint-flow-graph.svg taint-flow-graph.dot` 把污点流图转成可视化，人工核验链路。

## PoC

```yaml
# taint-config 节选（检测 Log4Shell 的最小组合）
sources:
- { kind: call, method: "<Main: java.lang.String getInput()>", index: result }

sinks:
- { method: "<javax.naming.InitialContext: java.lang.Object lookup(java.lang.String)>", index: 0 }

transfers:
- { method: "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>", from: 0, to: base }
- { method: "<java.lang.StringBuilder: java.lang.String toString()>", from: base, to: result }
```

```java
// 被分析的测试程序：外部字符串直达 logger.error
public class Main {
    public static void main(String[] args) {
        Logger logger = LogManager.getLogger();
        String poc = getInput();          // source 点
        logger.error(poc);                // 进入 log4j Lookup 机制
    }
    private static String getInput() {
        return "${jndi:ldap://<dnslog 子域>}";
    }
}
```

## 变体与关联

- 变体：入口方法无调用点时改用 `kind: param`（配合手工入口点注册）；字段注入场景用 `kind: field`；声明类型与实际类型不一致时用 `type:` 指定子类。
- 变体：分析范围用 `--scope APP/ALL/Reachable` 控制（Reachable 需先建调用图）；大型工程用 `-wc` 缓存世界构建加速迭代。
- 关联：利用侧见 JNDI 注入系列卡（如 `web-java-deserialization-jndi-log4j2-login-rce`、`web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase`）；工具工程化见 [[code-analysis-sast-taie-java-taint-audit-toolchain]]；入口点补全见 [[code-analysis-sast-taie-custom-entrypoint-mock-source-type-matching]]。

## 检测与防御

- 审计方视角：该配置可把"外部输入 → logger → JNDI lookup"的链路静态报出，但结论依赖 source/sink/transfers 的覆盖度；transfer 不全时污点会静默中断，低报不等于无漏洞，需用已知 payload 项目做回归。
- 开发方视角：升级 log4j2 至修复版本并移除 JNDI Lookup 类；禁用/限制 JNDI 与远程类加载；对日志参数做白名单过滤与转义；限制服务器出站 LDAP/RMI/DNS 流量。
- 检测：静态 TaintFlow 仅作候选，结合动态 DNS 回连验证（dnslog）与依赖版本扫描交叉确认。
