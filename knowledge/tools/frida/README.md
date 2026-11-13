# Frida

## 这层是什么

Hook、插桩与自动化。

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
| [Frida Arm64Writer 动态 NOP 掉 B.NE：绕过 native 分支暴露隐藏逻辑](tools-frida-arm64writer-nop-conditional-branch.md) | verified | high | 2026-11-06 |
| [Frida hook Resources.getString(int) 提取动态资源字符串：strings.xml 里找不到的 R.string.key 运行时直接打明文](tools-frida-hook-resources-getstring-dynamic-resource.md) | verified | high | 2026-11-11 |
| [Frida hook 动态加载 dex：enumerateClassLoaders 找到 DexClassLoader 并切换 classFactory.loader 后再 hook 其中类](tools-frida-enumerate-classloaders-dexclassloader-hook.md) | verified | high | 2026-11-09 |
| [Frida Java 层六类校验驱动：改参 Hook、静态/实例方法主动调用、静态/实例字段改写与 Java.choose 枚举](tools-frida-java-hook-static-instance-field-choose.md) | verified | high | 2026-11-07 |
| [Frida Native 层 Hook：导出/未导出函数定位、NativeFunction 主动调用、retval 修改与构造函数 $init](tools-frida-native-hook-export-unexport-retval-constructor.md) | verified | high | 2026-11-06 |
| [Frida RPC 主动调用 App 内加密函数批量取 anti-token/签名值，绕过 native 算法逆向复现请求](tools-frida-rpc-active-call-native-sign-function-bypass-reverse.md) | verified | high | 2026-11-08 |
| [Frida 主动调用 JNI 静态 native 方法导出 DES key/iv：Java.use 直接调 getkey/getiv，无需 hook 或逆向 so](tools-frida-active-call-static-native-jni-key-iv-des.md) | verified | high | 2026-11-09 |
| [Frida 源码魔改反检测：重命名进程/符号/线程/memfd/RPC 特征并编译 Android arm64 server](tools-frida-source-patch-anti-detection.md) | verified | high | 2026-11-06 |
| [Frida 访问与成员方法同名的字段要加下划线前缀：用 instance._name.value 赋值而不是 instance.name.value](tools-frida-field-method-same-name-underscore-prefix.md) | verified | high | 2026-11-09 |
| [Hook libart.so RegisterNatives 定位动态加载 so 名称与 native 函数偏移（绕过 ASLR 供 IDA 定位）](tools-frida-art-registernatives-dynamic-so-offset-locate.md) | verified | high | 2026-11-08 |
| [objection watch class_method 抓取 native 方法返回值：一条命令拿到 Encrypt() 明文](tools-frida-objection-watch-class-method-dump-return.md) | verified | high | 2026-11-08 |
| [加固 App 的 Frida hook：hook Application.attach(Context) 在壳完成 attachBaseContext 后取 ClassLoader，切换 classFactory.loader 再 hook 目标类](tools-frida-application-attach-classloader-hardened-app-hook.md) | verified | high | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
