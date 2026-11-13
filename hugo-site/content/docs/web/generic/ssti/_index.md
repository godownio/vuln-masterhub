---
title: 通用模板注入
weight: 1
---

# 通用模板注入

## 这层是什么

模板引擎识别、探测与利用。

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
| [Beetl getTemplate 模板串由业务参数拼接：rule 表达式经 print() 进入模板引擎 RCE](web-generic-ssti-beetl-gettemplate-user-rule-print-rce/) | verified | high | 2026-11-11 |
| [Beetl 模板 ${@类.方法} 静态调用：java.lang Runtime/Process 被禁后改用 Class.forName 反射串出命令执行](web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass/) | verified | high | 2026-11-08 |
| [Beetl 自定义白名单 NativeSecurityManager 被模板 public static test() 重写 callPattern 绕过，再 Beans.instantiate+SpEL RCE](web-generic-ssti-beetl-custom-whitelist-static-test-mutation/) | verified | medium | 2026-11-09 |
| [Bolt CMS 后台主题模板编辑改 index.twig + 清除缓存触发 Twig filter('system') 命令执行](web-generic-ssti-boltcms-admin-template-edit-twig-filter-system-rce/) | verified | high | 2026-11-12 |
| [BootDo 工作流待办消息存储后经 VelocityUtils.RenderData 求值：二阶 Velocity 模板注入 RCE](web-generic-ssti-bootdo-velocity-todomessage/) | verified | high | 2026-11-05 |
| [FastCMS 0.1.5 后台模板编辑 FreeMarker 注入：?new Execute 直接命令执行](web-generic-ssti-fastcms-template-edit-freemarker-rce/) | verified | high | 2026-11-05 |
| [FreeMarker SAFER_RESOLVER 绕过：第三方 TemplateModel、静态块、ProtectionDomain 与 ?api](web-generic-ssti-freemarker-safer-resolver-bypass/) | verified | high | 2026-11-05 |
| [FreeMarker SSTI 下用 object.class.getResourceAsStream 逐字节读取 classpath 配置](web-generic-ssti-freemarker-classpath-resource-read/) | verified | high | 2026-11-05 |
| [FuelCMS Dwoo 安全策略空实现：Closure::fromCallable 链式调用绕过沙箱执行命令](web-generic-ssti-dwoo-security-policy-empty-rce/) | verified | high | 2026-11-05 |
| [Java CMS 页面 Markdown 内容二次渲染 SSTI：${exec('ls /')} 保存后直接执行命令](web-generic-ssti-java-cms-markdown-page-exec/) | verified | medium | 2026-11-07 |
| [JFinalCMS 后台模板编辑 Enjoy SSTI：java.beans.Beans::instantiate 取 ScriptEngineManager 执行系统命令](web-generic-ssti-jfinalcms-enjoy-beans-instantiate-scriptengine-rce/) | verified | medium | 2026-11-11 |
| [MCMS 5.2.4 后台模板编辑路径穿越写 FreeMarker 模板：?new Execute 注入后台首页触发 RCE](web-generic-ssti-mcms-template-save-freemarker-execute/) | verified | medium | 2026-11-07 |
| [MCMS 5.3.1 writeFileContent 模板文件写入：`::$DATA` 绕过 ftl 后缀黑名单写 form.ftl，访问 /ms/cms/content/form 触发 FreeMarker RCE](web-generic-ssti-mcms-5-3-1-writefilecontent-ads-ftl-rce/) | verified | high | 2026-11-13 |
| [MCMS 后台模板编辑结合静态化/自定义页面渲染触发 FreeMarker SSTI RCE](web-generic-ssti-mcms-template-edit-freemarker-rce/) | verified | high | 2026-11-08 |
| [OTCMS 后台模板管理直接写入 Smarty 模板触发 SSTI：{otcms:} 前缀表达式求值，template_object 载荷执行 system 命令](web-generic-ssti-otcms-admin-template-smarty-rce/) | verified | high | 2026-11-12 |
| [Ruby ERB 模板注入：%x{} 直接执行系统命令读 flag](web-generic-ssti-ruby-erb-percent-x-command-exec/) | verified | high | 2026-11-06 |
| [Sinatra 类污染利用：改写 public_folder 读任意目录、覆盖 templates 哈希注入 ERB 模板拿 RCE](web-generic-ssti-sinatra-class-pollution-public-folder-templates/) | verified | medium | 2026-11-08 |
| [Smarty SSTI：默认非沙箱直接 RCE 与 Smarty 4/5 严格模式静态方法绕过](web-generic-ssti-smarty-direct-rce-v4-v5-bypass/) | verified | high | 2026-11-04 |
| [SSTI WAF 关键字拆分绕过：字符串拼接 + __eq__ 取 globals + os.popen 读文件](web-generic-ssti-waf-string-concat-eq-globals-bypass/) | verified | high | 2026-11-06 |
| [SSTI 报错回显外带：把命令输出作为非法参数由异常消息吐出](web-generic-ssti-error-message-exfiltration/) | verified | high | 2026-11-05 |
| [SSTI 模板引擎识别：决策树探测与报错特征对照](web-generic-ssti-engine-identification-decision-tree-errors/) | verified | high | 2026-11-04 |
| [Thymeleaf SSTI WAF 绕过：getClass().forName 反射 + 字符串拼接读取任意文件](web-generic-ssti-thymeleaf-reflection-files-read-waf-bypass/) | verified | medium | 2026-11-06 |
| [Twig SSTI：filter/map/reduce/sort 过滤器回调 system 实现命令执行与写文件](web-generic-ssti-twig-filter-map-reduce-callback-rce/) | verified | medium | 2026-11-04 |
| [Velocity.evaluate 字符串模板注入：用户输入拼入模板即反射 Runtime.exec；template.merge 仅在模板源码可控时成立](web-generic-ssti-velocity-evaluate-string-template-rce/) | verified | high | 2026-11-07 |
| [无回显 SSTI 的输出通道：把命令结果追加进「被源码路由回显」的文件，再由页面读回](web-generic-ssti-no-echo-append-source-route-readback/) | draft | medium | 2026-11-08 |
| [模板引擎定界符变体与条件盲注：禁用 $ 后 ~ 仍可解析（读解析器源码找等价字符），if+正则做逐字符 oracle](web-generic-ssti-template-delimiter-equivalent-conditional-blind/) | verified | medium | 2026-11-11 |
| [苹果CMS (MacCMS) 前台搜索 wd 注入 {if-...} 模板标签：经 str_replace 进入 $tpl->H，ifex() 正则提取条件后 @eval 执行](web-generic-ssti-maccms-ifex-template-tag-eval-injection/) | verified | high | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
