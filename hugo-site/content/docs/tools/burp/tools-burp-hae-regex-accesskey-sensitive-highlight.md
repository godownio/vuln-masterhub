---
id: tools-burp-hae-regex-accesskey-sensitive-highlight
title: Burp HaE 自定义正则被动标记与提取流量中的云 AccessKey/敏感字段：提取分组必须加括号、scope/exclude 配置与 20+ 厂商 AK 正则集
type: scenario
domain: tools
path: tools/burp
technique: burp-hae-regex-accesskey-highlight-extract
tags:
- burp
- hae
- regex
- secret-scanning
- accesskey
- cloud-credentials
- traffic-analysis
- info-leak
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V550
  verified_at: '2026-11-11T22:55:05+08:00'
  notes: 已对照原文与全部7张图核对：图02 GitHub gh0stkey/HaE Release；图03 Burp Extender→Extensions→Add→Select File 加载 jar；图04 HaE 标签页 Rules 列表（Email/Key泄露/AK头/敏感信息泄露，scope any body，engine nfa）；图05 Add Rule 对话框（Name/Regex/Color/Scope/Engine/Sensitive）；图06 Config 页（Config.yml 路径与 Exclude Suffix 长列表）；图07 Databoard 命中 Host/Email/Information。卡片对 Rules/Config/Databoard、'提取内容必须用 () 包住'、scope 语义、20+ 厂商 AK 前缀（AKIA/GOOG/AZ/IBM/OCID/LTAI/AKID/AK/AKLT/JDC_/UC/QY/LTC/YD/CTC/YYT/YY/CI/gcore 等）与 Exclude Suffix 去噪的表述均与原文/截图一致。修正两处：① PoC 中 GUID 形式规则原被归到 Azure，实为原文 IBM Cloud 的备选规则，已改为 IBM（或通用 GUID）并补上 (IBM[A-Za-z0-9]{10,40})；② 通用敏感字段规则原缺少最外层提取括号（HaE 要求 () 包裹提取内容，原文规则 1 为 ((?i)(...)) 整体包裹），已补外层括号，避免只提取到字段名。dedup：top 候选为 WIH 主动扫描、SecretScraper 爬虫、HAE 辅助 PII 导出、JumpServer 配置文件 AK 泄露等不同工具/场景，无同链；dup-scan.json 未涉及本卡。原文未标注受影响版本，affected_versions 保持空。未验证点：未实际安装 HaE 跑规则验证误报率。
url: /docs/tools/burp/tools-burp-hae-regex-accesskey-sensitive-highlight/
draft: false
kb_aliases:
- HaE
- Highlighter and Extractor
- HaE 规则
- HaE 正则
- Burp 高亮插件
- AccessKey 正则
- 云 AK 泄露检测
- 敏感信息高亮
---

## 一句话结论

HaE 是基于 Burp Extender API 的被动高亮/提取插件：把云厂商 AccessKey 前缀、`key=value` 形式的密钥/口令字段写成正则规则，HaE 会对经过 Burp 的请求/响应按 `scope` 实时匹配，命中即在 Proxy 历史中着色并汇总到 Databoard，从而在前后端分离应用的海量流量里先筛出凭证泄露线索；写规则时提取内容必须用 `()` 包住，否则规则不生效。

## 原理

- HaE 以 Burp Java 插件形式加载（`Extender -> Extensions -> Add -> Select File` 选 `HaE.jar`），注册 HTTP 监听器被动接收 Burp 已经收发的报文，不额外发请求，因此不会改变目标流量或引入主动扫描噪声。
- 每条规则由 Name/Regex/Color/Scope/Engine/Sensitive 组成。`Scope` 决定匹配范围（`request`/`response` 数据包，`header`/`body`/`any`），`Regex` 用 Java 正则引擎对选定范围做匹配；命中后该报文在 Proxy 历史条目标上 Color 颜色，并把命中的提取内容写入 Databoard 面板集中检索。
- 之所以能用于找密钥：云厂商 AccessKey 有稳定的前缀/长度特征（AKIA= AWS、LTAI=阿里云、AKID=腾讯云、AKIA/AKLT 等），`access_key=`、`password=` 等字段名也相对固定；用正则直接匹配报文文本，无需理解业务参数结构，就能把"可能含凭证"的报文从流量里挑出来。
- HaE 对正则的要求与常见脚本语言不同：Java 正则本身不做提取组语义，插件要求用 `()` 把要提取的内容包起来（例如匹配 Shiro 特征写 `rememberMe=delete` 不会提取，写成 `(rememberMe=delete)` 才会把这段显示到 Databoard）。
- 由于匹配范围包含整个 body，图片/字体/CSS 等二进制或大文本响应会产生大量误报与性能开销，`Config -> Exclude Suffix` 可排除常见静态后缀；通用短前缀规则（如 `AK`、`AZ`、`YY`、`CI`）误报高，通常要配合引号/赋值符/`$` 锚点收窄。

## 触发条件

- 使用 Burp 代理目标进行测试，插件已加载且规则启用（`Loaded` 勾选）。
- 目标响应或请求中包含云 AccessKey、`access_key`/`secret_key`/`password` 等敏感字段，或前端 JS/接口回显了配置信息。
- 报文为文本形态（JSON/JS/HTML/form），二进制响应会被排除后缀或引擎过滤掉。

## 利用步骤

1. 安装：Burp `Extender -> Extensions -> Add`，Extension type 选 Java，选择 `HaE.jar`，加载后主界面出现 `HaE` 标签页（自带一条 `Email` 规则，可用于确认插件工作）。
2. 新建规则：`Rules -> Add`，填写 Name（按用途命名）、Regex（提取内容用 `()` 包住）、Color、Scope（抓响应泄露一般选 `response` + `body`/`any`）、Engine（默认 NFA）、Sensitive（是否大小写敏感）。
3. 降低噪声：`Config -> Exclude Suffix` 填入 `3g2|3gp|7z|aac|abw|...|jpg|png|zip` 等静态后缀；`Config Path` 保持默认，规则会持久化到本地 YAML。
4. 被动抓取：正常浏览/测试目标，HaE 在 Proxy 历史中给命中报文着色；`Databoard` 面板按规则聚合命中记录，可直接查看命中的 Host、字段值与完整报文上下文。
5. 人工验证：对 Databoard 中的候选逐条回到原报文确认是否为真实凭证（排除静态示例/占位符），再按云厂商特征做格式校验与后续利用评估。

## PoC

HaE Regex 列可直接使用的厂商前缀规则（每条整体作为一个规则；提取内容已用括号包住）：

```text
# AWS AccessKey ID
(AKIA[A-Za-z0-9]{16})
# Google Cloud
(GOOG[\w\W]{10,30})
# Azure：AZ 前缀
(AZ[A-Za-z0-9]{34,40}$)
# IBM Cloud（或通用 GUID 形式）
(IBM[A-Za-z0-9]{10,40})
([a-zA-Z0-9]{8}(-[a-zA-Z0-9]{4}){3}-[a-zA-Z0-9]{12}$)
# 阿里云
(LTAI[A-Za-z0-9]{12,20})
# 腾讯云
(AKID[A-Za-z0-9]{13,20})
# 华为云
(AK[\w\W]{10,62})
# 百度云
(AK[A-Za-z0-9]{10,40})
# 京东云
(JDC_[A-Z0-9]{28,32})
# 火山引擎
(AKLT[a-zA-Z0-9-_]{0,252})
# Oracle Cloud
(OCID[A-Za-z0-9]{10,40})
# 其它云（UCloud/青云/金山云/联通云/移动云/电信云/一云通/用友云/南大通用/G-Core）
(UC[A-Za-z0-9]{10,40})
(QY[A-Za-z0-9]{10,40})
(AKLT[a-zA-Z0-9-_]{16,28})
(LTC[A-Za-z0-9]{10,60})
(YD[A-Za-z0-9]{10,60})
(CTC[A-Za-z0-9]{10,60})
(YYT[A-Za-z0-9]{10,60})
(YY[A-Za-z0-9]{10,40})
(CI[A-Za-z0-9]{10,40})
(gcore[A-Za-z0-9]{10,30})
```

通用敏感字段规则（字段名 + 赋值符 + 带引号值，`(?i)` 大小写不敏感，可按需裁剪字段表）：

```text
((?i)((access_key|accesskey|access_key_id|access_token|secret_key|secretkey|secret_access_key|api_key|apikey|api_secret|app_secret|appsecret|app_key|client_secret|private_key|password|passwd|pwd|auth_token|authorization)[a-z0-9_\-]{0,25})(=|>|:=|<=|=>|:).{0,5}['" ]([0-9a-zA-Z\-_=]{12,64})['" ])
```

## 变体与关联

- 变体：把同一组规则复制到 `request` scope，可发现客户端主动提交的密钥/口令字段；`scope=response` 更适合找服务端回显的配置与调试信息。
- 变体：用 `(?i)` 内联标志做大小写不敏感匹配；`Sensitive` 字段与该标志共同决定大小写行为，规则间不要重复。
- 变体：把高误报的短前缀规则（`AK`、`AZ`、`YY`、`CI`）改写成"引号/等号上下文 + 长度区间 + 行尾锚点"的组合，可显著降低误报。
- 关联：[[pentest-recon-wih-web-infohunter-sensitive-leak-scan]]（主动批量页面文本扫描云 AK/Token）、[[pentest-recon-secretscraper-crawl-regex-sensitive-leak-scan]]（爬虫+规则匹配）、[[pentest-recon-llm-provider-api-key-frontend-js]]（前端 JS 中的大模型 API Key）、[[web-generic-auth-js-api-discovery-unauth-pii-mass-export]]（HAE 标记身份证/手机号辅助 PII 批量导出）；HaE 的差异是被动、基于 Burp 流量、零额外请求。
- 边界：HaE 只能看到经过 Burp 的流量，移动端/非代理流量看不到；规则是纯文本正则，加密报文、压缩响应、二进制协议需先解密/解压；命中只是线索，必须人工确认凭证有效性与权限。

## 检测与防御

- 防守视角：云 AccessKey/SecretKey 不应出现在任何前端资源、接口响应或日志中；前端只使用临时 STS 凭证或后端签名代理。
- 对响应中的敏感字段做统一脱敏（掩码/删除），调试接口与配置接口加鉴权并在生产关闭。
- 将 `AKIA`/`LTAI`/`AKID` 等前缀与 `access_key=`、`secret_key=` 等模式纳入 CI 密钥扫描与网关出站检测，发现即轮换；AK 按最小权限授权并设置使用告警。
- 防守方也可反向利用同类规则审计自有流量与日志，确认是否存在凭证泄露面。
