---
id: defense-detection-tomcat-filter-memshell-hotpatch-vmtool-remove
title: Tomcat Filter 内存马不重启处置：Arthas 热加载改写与 vmtool 移除 FilterMap/FilterDef
type: scenario
domain: defense
path: defense/detection
technique: arthas-hotpatch-filter-memshell-vmtool-remove
tags:
- java
- tomcat
- memshell
- filter
- arthas
- retransform
- vmtool
- incident-response
- godzilla
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V143
  verified_at: '2026-11-06T06:02:21+08:00'
  notes: 已对照原文与图01-08核对：/favicondemo.ico 重复 POST 与 pass1024 参数、ss/lsof 定位 PID 1477766、Arthas 4.1.9、sc *.Filter 命中 com.summersec.x.GodzillaFilter、classloader 中出现 TemplatesImpl$TransletClassLoader、sc -d code-source 为空、jad 反编译的 AES 密钥/Pwd/path/addFilter/doFilter 逻辑，以及热加载（jad --source-only、mc、retransform、retransform --deleteAll）与 vmtool removeFilterMap/removeFilterDef 命令均一致。小问题：卡内提到清空 toString，原文反编译源码未见 toString 定义，属泛化表述，不影响结论。原文未给 Tomcat 版本，未设 affected_versions。未验证点：原文未展示 retransform/vmtool 执行后的实际回显，未复跑；frontmatter 无 sources/source_url。
url: /docs/defense/detection/defense-detection-tomcat-filter-memshell-hotpatch-vmtool-remove/
draft: false
kb_aliases:
- GodzillaFilter 查杀
- Arthas retransform 内存马
- vmtool removeFilterMap
- removeFilterDef
- 内存马热加载
- 不重启清除内存马
- TemplatesImpl 内存马溯源
---

## 一句话结论

对 Tomcat 中的哥斯拉 Filter 型内存马，先用 Arthas 的 `sc *.Filter`、`sc -d`、`classloader` 定位无 `code-source` 的可疑类，并从 `TemplatesImpl$TransletClassLoader` 判断注入链是反序列化；应急处置可不重启：用 `jad --source-only` 导出源码、把 `doFilter` 改成放行逻辑后 `mc` 编译并 `retransform` 热替换，或用 `vmtool` 直接 `removeFilterMap`/`removeFilterDef` 拔除容器映射与定义。

## 原理

- **Filter 内存马形态**：恶意类通常 `extends ClassLoader` 并 `implements Filter`，持有 AES 密钥、连接密码和触发路径（样本为 `xc=3c6e0b8a9c15224a`、`Pwd=pass1024`、`path=/favicondemo.ico`）。`addFilter()` 通过 `ServletContext` 反射取到 `ApplicationContext` 再取 `StandardContext`，把生命周期状态置为 `STARTING_PREP`，调用 `addFilter`/`addMappingForUrlPatterns`/`filterStart` 完成注册，并把自身 `FilterMap` 调整到数组首位；`doFilter` 读取请求参数 `Pwd`，base64 解码后 AES 解密，首次把 payload `defineClass` 存入 session，之后实例化执行，并按 `md5[:16] + base64(AES(结果)) + md5[16:]` 回包。整个过程只存在于 JVM 内存，删除 JSP 或重启前一直有效。
- **检测与注入链判断**：流量上表现为同一路径（如 `/favicondemo.ico`）反复出现带 `pass1024=<base64>` 的 POST；上机后用 `ps`/`ss` 找到 Java 进程，attach Arthas。`sc *.Filter` 列出所有 Filter 实现类，`sc -d <类名>` 的 `code-source` 为空说明类不是从磁盘 JAR/目录加载；`classloader` 中若出现 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl$TransletClassLoader`，说明恶意字节码来自 `TemplatesImpl` 动态加载，通常意味着系统存在反序列化入口，而不是单纯的文件上传。
- **热加载处置**：`retransform` 会用新的类字节替换 JVM 中已加载的类。把 `doFilter` 改成只调用 `chain.doFilter` 放行，并清空 `equals`/`toString` 等可能再次触发恶意逻辑的方法，重新编译后 `retransform`，即可在不重启的情况下让原触发路径失效。`retransform --deleteAll` 可撤销所有 retransform、恢复原始字节码。
- **vmtool 内存拔除**：`StandardContext` 的 `filterMaps`/`filterDefs` 保存了 Filter 的 URL 映射与定义。用 `vmtool` 取到 `StandardContext` 实例后，按 `filterName`（样本为 `/favicondemo.ico`）过滤并调用 `removeFilterMap`、`removeFilterDef`，即可把恶意 Filter 从容器结构中移除；之后访问原路径不再进入内存马。
- **为什么成立**：两种方式都直接作用于 JVM 运行时对象——`retransform` 改的是类字节，`vmtool` 改的是容器注册表；不依赖重启，也不依赖磁盘文件，因此适合生产环境应急处置。处置后仍需修复初始入口（反序列化/上传/表达式注入），否则可再次注入。

## 触发条件

- 目标为 Tomcat（或兼容 `StandardContext` 结构的 Servlet 容器），已确认存在 Filter 型内存马。
- 排查者拥有与目标 JVM 相同用户或可 attach 的权限，Arthas 可用。
- 已知或能通过 `sc *.Filter` 找到恶意类名/`filterName`（样本为 `com.summersec.x.GodzillaFilter`、`/favicondemo.ico`）。
- 生产环境不允许重启，或希望先止血再安排重启。

## 利用步骤

1. 流量侧确认异常：同一路径反复 POST，参数名与密码一致（如 `pass1024=<base64>`），响应为 16 位 MD5 + Base64 + 16 位 MD5。
2. 上机 `ps`/`ss` 定位 Java 进程与外联，记下 PID。
3. `java -jar arthas-boot.jar` 选择该 PID，`dashboard` 查看线程/内存。
4. `sc *.Filter` 找可疑 Filter 类；`sc -d <类名>` 确认 `code-source` 为空；`classloader` 确认是否由 `TemplatesImpl$TransletClassLoader` 加载，判断注入链。
5. `jad <类名>` 反编译，确认 `doFilter`、`addFilter`、AES 密钥、密码、触发路径等恶意逻辑。
6. **热加载处置**：`jad --source-only <类名> > /tmp/<类名>.java`，编辑源码把 `doFilter` 改为 `chain.doFilter(req, resp)` 放行，清空 `equals`/`toString` 等恶意逻辑；`mc /tmp/<类名>.java -d /tmp` 编译；`retransform /tmp/<包路径>/<类名>.class` 热替换。需要恢复时 `retransform --deleteAll`。
7. **或 vmtool 拔除**：
   ```text
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext \
     --express 'instances[0].removeFilterMap(instances[0].findFilterMaps().{? #this.getFilterName()=="/favicondemo.ico"}[0])'
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext \
     --express 'instances[0].removeFilterDef(instances[0].findFilterDefs().{? #this.getFilterName()=="/favicondemo.ico"}[0])'
   ```
8. 访问原恶意路径验证已失效；继续排查初始入口（反序列化、上传、表达式注入）并修复，必要时安排重启确认无残留。

## PoC

```text
# 定位
java -jar arthas-boot.jar
dashboard
sc *.Filter
sc -d com.summersec.x.GodzillaFilter
classloader
jad com.summersec.x.GodzillaFilter

# 热加载改写
jad --source-only com.summersec.x.GodzillaFilter > /tmp/GodzillaFilter.java
mc /tmp/GodzillaFilter.java -d /tmp
retransform /tmp/com/summersec/x/GodzillaFilter.class
retransform --deleteAll

# vmtool 移除映射与定义
vmtool --action getInstances --className org.apache.catalina.core.StandardContext \
  --express 'instances[0].removeFilterMap(instances[0].findFilterMaps().{? #this.getFilterName()=="/favicondemo.ico"}[0])'
vmtool --action getInstances --className org.apache.catalina.core.StandardContext \
  --express 'instances[0].removeFilterDef(instances[0].findFilterDefs().{? #this.getFilterName()=="/favicondemo.ico"}[0])'
```

## 变体与关联

- **类名/路径变体**：`filterName` 不一定是 URL 路径，可能是“类简名+时间戳”；按 `sc *.Filter` 与 `findFilterMaps()` 的实际结果替换过滤条件。
- **内存马类型变体**：Servlet/Listener/Valve 型需改用对应的 `StandardContext` 字段与移除 API；Agent/transformer 型见 [[defense-detection-arthas-agent-memshell-detect-remove]]。
- **检测流程变体**：`java-memshell-scanner` + Arthas + Copagent 的组合见 [[defense-detection-tomcat-memshell-scanner-arthas]]。
- **攻击卡关联**：哥斯拉 FilterShell 的注入与注册细节见 [[web-java-component-tomcat-godzilla-filtershell-memshell]]；TemplatesImpl 反序列化入口可按 classloader 线索继续排查。

## 检测与防御

- **检测**：同一路径的异常 POST 与 `pass<密码>=<base64>` 参数；响应为 MD5+Base64+MD5 三段式；`sc *.Filter` 出现陌生类、`code-source` 为空、classloader 为 `TemplatesImpl$TransletClassLoader`；`filterMaps` 中出现 `/*` 或异常路径且排在链首；`filterDefs` 中的类名伪装成框架类。
- **防御**：修复 `TemplatesImpl` 等反序列化入口与文件上传/表达式注入；部署 RASP/Java Agent 监控 `defineClass`、`addFilter`、`filterConfigs` 修改；限制 Arthas 等诊断工具的访问权限；应急处置后安排重启并复查，确认内存马未随 JSP 删除而残留；保留热加载/`vmtool` 操作记录以便审计。
