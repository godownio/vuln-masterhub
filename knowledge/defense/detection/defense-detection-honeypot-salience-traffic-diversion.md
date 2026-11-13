---
id: defense-detection-honeypot-salience-traffic-diversion
title: 公网蜜罐甜度与引流：独立域名/证书 + 仿真业务 + 演练常见漏洞诱饵，借 GitHub"泄露代码"与测绘平台收录吸引攻击者
type: scenario
domain: defense
path: defense/detection
technique: honeypot-public-salience-diversion-jsonp-concealment
aliases:
- 蜜罐甜度
- 蜜罐引流
- 瓜甜速来
- 请君入瓮
- 公网蜜罐运营
- 蜜罐被攻击者发现
tags:
- defense
- detection
- deception
- honeypot
- traffic-diversion
- attribution
- hw
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V625
  verified_at: '2026-11-12T22:12:53+08:00'
  notes: 已对照原文PPT全部19张图核对：卡片『甜度/引流/探针隐藏』三块与图16蜜罐tips逐条对应（独立域名+ip+证书、仿真后台业务+交互、悬挂shiro等演练高频漏洞入口；GitHub投放泄露代码、FOFA/Hunter测绘平台提交资产、搜索引擎收录；jsonp探针仅放登录后/后台页面）；图17思路延伸、图8-10蜜罐反制与溯源、非蜜罐OSINT、图11-15四个溯源案例均属skipped场景（既有卡已覆盖或仅为要点无PoC），跳过理由成立。affected_versions无关：防守经验要点，原文无版本标记，未set-versions。dedup：与pentest-recon-honeypot-jsonp-attacker-attribution-evasion（JSONP探针采集机制+红队规避）为互补环节非同链，与defense-detection-honeytoken-breadcrumb-deception-deployment（内网蜜币面包屑）环境不同；dup-scan.json无涉及本篇pair。原子性：整篇tips本质是公网蜜罐曝光面运营一个闭环，不拆。保留。
---

## 一句话结论

HW/重保期间想让公网蜜罐真正被攻击者命中，需要同时解决"能被搜到"和"看起来值得打"两个问题：用独立域名 + 独立 IP + 有效证书伪装成真实业务站点、仿真后台类业务并保留交互、布置演练中攻击者常用的漏洞入口（如 shiro 默认口令），再通过 GitHub 投放"泄露代码"、在 FOFA/Hunter 等测绘平台提交资产、争取搜索引擎收录来主动引流；采集探针（jsonp 等）则只放在登录后页面，避免未登录就被识破。

## 原理

- **攻击者的发现路径决定蜜罐的曝光方式**：HW 攻击者通常先通过测绘平台（FOFA/Hunter）、搜索引擎、GitHub 泄露代码和子域名收集寻找入口；蜜罐如果只部署不投放，天然流量极低。把蜜罐资产"喂"到上述渠道，等于在攻击者的侦察面上增加暴露面。
- **甜度 = 可打性 + 真实感**：独立域名、独立 IP、有效证书让资产看起来像正规业务而非默认部署；仿真后台类业务（登录页、文件上传、管理面板）并保留有限交互，能让扫描器与人工都认为"有东西可打"；悬挂演练中高频被利用的漏洞（如 shiro 默认密钥）作为入口诱饵，能直接接住批量打点流量。
- **jsonp 探针的暴露风险**：若探针在未登录的首页就加载第三方 JSONP，反蜜罐插件/人工审查很容易识别出蜜罐；把探针放在登录后或后台页面触发，攻击者先"打进来"再被采集，隐蔽性更好。
- **GitHub "泄露代码"投毒**：在公开仓库投放带内部配置/凭据/内网地址的伪泄露代码，指向蜜罐资产；攻击者扫描 GitHub 找入口时会顺着配置访问蜜罐，这条路径流量精准且意图明确。
- **边界**：蜜罐不得使用真实凭据、不得承载真实业务数据、不得对外提供可被用于二次攻击的能力；引流与采集须在授权与合规范围内。

## 触发条件

- 组织在演练期间运营公网蜜罐，具备独立域名、IP 与证书资源，能部署仿真业务与漏洞诱饵。
- 能在 GitHub 等公开渠道投放伪泄露材料，并能向测绘平台提交/收录资产。
- 有后端接收蜜罐采集数据（探针回传、访问日志）并具备溯源研判流程。
- 全程在授权演练与法律边界内。

## 利用步骤

1. **提高甜度**：为蜜罐配置独立域名 + 独立 IP + 有效 TLS 证书；部署仿真的后台/业务页面（登录框、文件管理、API 文档）并保留交互；按演练威胁情报悬挂高频漏洞入口（如 shiro 默认 key、常见弱口令管理后台）。
2. **GitHub 引流**：投放包含"内部地址/凭据"的伪泄露代码或配置文件，指向蜜罐域名/IP，等待攻击者从代码仓库侦察时命中。
3. **测绘平台引流**：在 FOFA/Hunter 等平台提交蜜罐资产（ICP/证书/标题特征），加速被收录与检索。
4. **搜索引擎收录**：通过站长工具提交链接或外链，使蜜罐页面进入搜索引擎索引。
5. **探针隐藏**：jsonp/JS 采集探针只挂在登录后或后台页面，未登录首页不加载第三方脚本，降低被反蜜罐插件识别的概率。
6. **观测与运营**：集中收集蜜罐访问日志、探针回传与漏洞触发记录，按"是否真实攻击意图"研判并联动溯源（见 JSONP 探针与 IP 溯源卡）。

## PoC

无攻击性 PoC（原始材料为防守方经验要点）。部署侧检查清单：

```text
[ ] 独立域名 + 独立 IP + 有效证书（与业务风格一致的标题/favicon）
[ ] 仿真后台业务 + 有限交互（登录、上传、列表页）
[ ] 悬挂演练高频漏洞入口（shiro 默认 key、弱口令、未授权 API）
[ ] GitHub 伪泄露代码指向蜜罐资产
[ ] FOFA/Hunter 提交资产、搜索引擎收录
[ ] jsonp/探针仅在登录后页面加载
[ ] 采集数据集中落库 + 溯源研判流程
```

## 变体与关联

- 关联：[[defense-detection-honeytoken-breadcrumb-deception-deployment]]（内网蜜币/面包屑诱饵，与公网引流互补）、[[pentest-recon-honeypot-jsonp-attacker-attribution-evasion]]（JSONP 探针采集机制与红队规避）、[[pentest-recon-honeypot-identification-hfish-fingerprint-momentjs-ssh-rule]]（蜜罐识别，红队应对本卡手法的视角）、[[defense-incident-response-attacker-ip-attribution-icp-aliyun-recovery-cross-validation]]（蜜罐命中后的 IP 归属溯源）。
- 变体：用云函数/云主机承载蜜罐；多套蜜罐资产组成蜜网；按攻击者来源区域部署不同语言/风格的诱饵。

## 检测与防御

- **红队识别视角**：域名注册时间新、证书签发时间与站点内容不符、页面存在第三方 jsonp 探针、资产指纹与宣称业务不一致、测绘平台标注为蜜罐特征——这些都提示蜜罐。
- **防守合规**：蜜罐与生产隔离、不使用真实凭据与数据、采集的个人信息最小化并限定用途、投放伪泄露材料不得损害第三方。
- **运营**：定期轮换诱饵与漏洞入口，避免攻击者标记蜜罐资产；监控蜜罐是否被攻陷并当作跳板。
