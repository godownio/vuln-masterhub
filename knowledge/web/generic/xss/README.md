# XSS

## 这层是什么

反射/存储/DOM XSS、绕过与利用。

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
| [.htaccess 注入 highlight.string / docref_root 配置造成 XSS](web-generic-xss-php-config-highlight-docref.md) | verified | high | 2026-11-05 |
| [AI 对话页面输出型 XSS：提示词诱导模型输出 HTML，前端把 AI 回复当富文本渲染即执行](web-generic-xss-ai-chat-output-prompt-injection.md) | verified | high | 2026-11-06 |
| [AngularJS 表达式沙箱逃逸：constructor.constructor 与 charAt 覆写绕过](web-generic-xss-angularjs-sandbox-escape.md) | verified | high | 2026-11-05 |
| [ChatterMate <=1.0.8 存储型 XSS：widget 聊天消息未过滤落库，后台会话查看触发 iframe javascript URI 窃取管理员凭据（CVE-2026-24399）](web-generic-xss-chattermate-widget-message-stored-xss.md) | verified | high | 2026-11-06 |
| [CSP script-src 'self' 下通过同源 JSONP 回调注入执行任意 JS](web-generic-xss-csp-self-jsonp-callback-bypass.md) | verified | high | 2026-11-05 |
| [data: iframe 配合无源校验的 postMessage 接收端导致父页面 DOM XSS](web-generic-xss-data-iframe-postmessage-innerhtml.md) | verified | high | 2026-11-05 |
| [Dify ECharts 代码块 new Function 存储型 XSS：聊天日志触发并邀请自己加入工作区（成员）](web-generic-xss-dify-echarts-new-function-workspace-takeover.md) | verified | high | 2026-11-06 |
| [DOM Clobbering 劫持 window 配置变量 + DOMPurify 放行 form 导致 bot cookie 外带](web-generic-xss-dom-clobbering-window-globals-config-exfil.md) | verified | high | 2026-11-06 |
| [DOM Clobbering 劫持第三方库配置对象：HTMLCollection 静默赋值失效 + 库内 gadget 删 escapeHtml 后注入 iframe onload](web-generic-xss-dom-clobbering-library-config-gadget.md) | verified | medium | 2026-11-07 |
| [DOM Clobbering：用 id/name 元素覆盖未声明的全局变量](web-generic-xss-dom-clobbering-window-name-collision.md) | verified | high | 2026-11-05 |
| [DOMPurify 3.1.0 mXSS 绕过：506 层扁平化 + caption 突变把 onerror 弹入 HTML 命名空间](web-generic-xss-dompurify-mxss-caption-flattening.md) | verified | high | 2026-11-05 |
| [DOMPurify 3.1.1 深度限制绕过：form 命名属性劫持 parentNode 重新计数触发 mXSS](web-generic-xss-dompurify-parentnode-clobbering-depth-bypass.md) | verified | high | 2026-11-05 |
| [DOMPurify 净化后 textContent 再写 innerHTML：用 i 标签拆分重组出可执行标签](web-generic-xss-dompurify-textcontent-innerhtml-reparse.md) | verified | high | 2026-11-07 |
| [Draft List 短代码先 kses 过滤后替换占位符，草稿标题逃逸属性触发存储型 XSS](web-generic-xss-wordpress-draftlist-kses-before-placeholder.md) | verified | high | 2026-11-05 |
| [Electron 客户端 XSS + preload IPC curl：file:// 读取本地 flag 并借 Bot 写回管理员简介](web-generic-xss-electron-ipc-curl-file-read-bot-cookie.md) | verified | high | 2026-11-07 |
| [ExtJS 4.2.x 组件默认 HTML 渲染 XSS：MessageBox 错误弹窗与 ComboBox displayField](web-generic-xss-extjs-messagebox-combobox-html-render.md) | verified | medium | 2026-11-07 |
| [Goldmark 先查危险协议后做 HTML 实体还原：javascript&colon; 绕过 Markdown 链接过滤（CVE-2026-5160）](web-generic-xss-goldmark-markdown-entity-url-check.md) | verified | high | 2026-11-05 |
| [h3blog 后台存储型 XSS：注册用户昵称与 X-Forwarded-For 登录日志未编码，管理员查看用户/操作日志时触发](web-generic-xss-h3blog-username-xff-log-stored-xss.md) | verified | high | 2026-11-07 |
| [htmlspecialchars 默认 flags 未转义单引号导致单引号属性上下文 XSS](web-generic-xss-htmlspecialchars-single-quote-attribute.md) | verified | high | 2026-11-04 |
| [iframe.srcdoc 拼接用户 HTML：srcdoc 继承父源，内联脚本读取同源 Cookie](web-generic-xss-iframe-srcdoc-user-html.md) | verified | high | 2026-11-07 |
| [JavaScript 代码上下文注入：字符串闭合、表达式位置与模板字符串插槽](web-generic-xss-javascript-context-injection.md) | verified | high | 2026-11-05 |
| [JSON 只转义引号未转义反斜杠配合 eval 消费导致代码注入](web-generic-xss-json-eval-backslash-escape.md) | verified | high | 2026-11-05 |
| [JustHTML Raw-text 元素原样序列化：style 内 </style> 突破导致 mXSS（GHSA-qvc2-mg72-jjhx）](web-generic-xss-justhtml-rawtext-style-serialization-mxss.md) | verified | high | 2026-11-05 |
| [JWT 自定义 claim 注入 CSP report-uri：补写 script-src/connect-src 绕过默认 CSP](web-generic-xss-csp-report-uri-claim-injection.md) | verified | high | 2026-11-05 |
| [lxml_html_clean 先删反斜杠再匹配 @import：CSS Unicode 转义 @\69mport 绕过清理器（CVE-2026-28348）](web-generic-xss-lxml-html-clean-css-unicode-escape-import.md) | verified | medium | 2026-11-05 |
| [MaxSite CMS 上传插件缺权限校验：低权限用户上传 HTML 同源读取管理员页面](web-generic-xss-maxsite-upload-missing-authz-admin-page-exfil.md) | verified | high | 2026-11-06 |
| [meta CSP 悬空标记绕过：title 提前闭合 + 未闭合 img 属性吞掉 CSP meta](web-generic-xss-meta-csp-dangling-markup-bypass.md) | verified | high | 2026-11-07 |
| [newbee-mall 商品详情 goodsDetailContent 原样渲染：后台富文本注入形成前台存储型 XSS](web-generic-xss-newbeemall-goods-detail-stored.md) | verified | high | 2026-11-05 |
| [O2OA REST 设计器/配置接口批量存储型 XSS：无输出编码与无全局 XSS Filter](web-generic-xss-o2oa-rest-designer-mass-stored-xss.md) | verified | high | 2026-11-05 |
| [PDF 内嵌 JavaScript 配合上传后内联预览触发 XSS](web-generic-xss-pdf-javascript-inline-preview.md) | verified | medium | 2026-11-05 |
| [Roundcube CVE-2024-42009：邮件正文 SVG animate 事件 XSS 窃取信箱与密码重置令牌](web-generic-xss-roundcube-cve-2024-42009-email-token-theft.md) | verified | high | 2026-11-05 |
| [script 标签被过滤时的 XSS 替代执行载体：SVG、事件处理器与 javascript 伪协议](web-generic-xss-scriptless-execution-vectors.md) | verified | high | 2026-11-04 |
| [Swagger UI configUrl/url 参数加载外部配置导致 DOM XSS](web-generic-xss-swagger-ui-configurl-dom-xss.md) | verified | medium | 2026-11-05 |
| [Tmall_demo 三处存储型 XSS：商品名称/标题、订单详细地址/卖家留言、管理员昵称未编码回显](web-generic-xss-tmall-product-order-admin-nickname-stored.md) | verified | medium | 2026-11-07 |
| [WAF 保护下的存储型 XSS：冷门 HTML5 事件 FUZZ、逗号表达式隐藏 alert 特征与长度截断适配](web-generic-xss-waf-cold-event-comma-operator-truncation.md) | verified | high | 2026-11-05 |
| [wkhtmltopdf HTML 注入读本地文件并破解 /etc/shadow 登录后台](web-generic-xss-wkhtmltopdf-local-file-read-shadow-login.md) | verified | high | 2026-11-06 |
| [XSS 字符替换/黑名单绕过：双写、大小写、空白替代与实体编码](web-generic-xss-filter-bypass-encoding-obfuscation.md) | verified | high | 2026-11-04 |
| [前端 escapeHTML 使用非全局 replace 只替换首个尖括号，前缀填充即可绕过](web-generic-xss-nonglobal-replace-first-match-bypass.md) | verified | high | 2026-11-05 |
| [前端 hash 路由参数直入 jQuery .html() 导致 DOM XSS](web-generic-xss-hash-route-param-jquery-html-sink.md) | verified | high | 2026-11-05 |
| [华夏ERP V2.3 多业务模块存储型 XSS：采购商品、客户、供应商与收支项目字段未编码](web-generic-xss-xiahuia-erp-multi-module-stored.md) | verified | medium | 2026-11-06 |
| [双重 URL 解码差异配合 setTimeout 字符串参数导致 DOM XSS](web-generic-xss-double-url-decode-settimeout-sink.md) | verified | high | 2026-11-05 |
| [后端 delScriptTag 仅删 script/style，直连接口绕过前端实体编码导致存储型 XSS](web-generic-xss-backend-script-style-blacklist-api-bypass.md) | verified | high | 2026-11-05 |
| [客服对话 HTML 实体编码绕过尖括号过滤：decodeHtmlEntities + innerHTML 导致存储型 XSS 窃取客服 Cookie](web-generic-xss-html-entity-decode-innerhtml-support.md) | verified | high | 2026-11-05 |
| [属性内联 JS 只转义字面单引号，&apos; 实体在 HTML 解析阶段还原导致闭合](web-generic-xss-apos-entity-attribute-js-breakout.md) | verified | medium | 2026-11-05 |
| [未授权新增热点问题接口导致后台存储型 XSS](web-generic-xss-unauth-stored-xss-hot-question.md) | verified | high | 2026-11-05 |
| [注册资料未编码导致后台用户列表存储型盲打 XSS](web-generic-xss-admin-blind-stored-registration.md) | verified | high | 2026-11-05 |
| [路径段原样回显导致反射型 XSS（SVG onload）](web-generic-xss-path-segment-reflected-svg.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
