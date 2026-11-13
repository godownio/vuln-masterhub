---
id: web-generic-auth-content-site-packed-id-2pow32-step-paywall-bypass
title: 内容站付费章节越权：64 位内容 ID 按 2^32 步进打包，预览/免费 URL 规律爆破取得付费章节全文
type: scenario
domain: web
path: web/generic/auth
technique: content-packed-numeric-id-step-paywall-bypass
tags:
- web
- auth
- idor
- access-control
- enumeration
- numeric-id
- integer-packing
- paywall
- content-site
- burp-intruder
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V594
  verified_at: '2026-11-12T15:41:06+08:00'
  notes: 已对照原文及全部 8 张截图核对：图 04 章节 URL 数字连续两行差 4294967296（89178884177026193→89178888471993489→89178892766960785，本地验算成立；原文“第三行减第一行还是4294967296”系口误，卡内按“连续两行”表述正确）；图 03 脚本 book_id=4356380975/4356462058、Process 1/1176；图 06 Burp Intruder 起始 6749011871265265967、Step=2^32 的 5 个 200（长度 446489/363208/305712/41022/25439，随后 404 约 650）与卡内 PoC 一致；图 02 KS(url) 返回 Promise 明文；图 07 预览页“此章为付费章节”；图 05/08 下载 txt 含全文。卡内已说明“原文未解释服务端为何按数字 ID 返回全文”，confidence=medium 合理。dedup top 候选（课程 courseId 遍历、VIP 直链、学号 AES 枚举、userId 遍历等）均不同链。未在本机复跑。
url: /docs/web/generic/auth/web-generic-auth-content-site-packed-id-2pow32-step-paywall-bypass/
draft: false
kb_aliases:
- 小说站付费章节越权
- 2^32 步进
- 4294967296 遍历
- chapterId 打包 ID
- 付费墙绕过
- novel-content 接口爆破
- 64 位数字 ID IDOR
---

## 一句话结论

小说/内容站点把书籍与章节打包进一个 64 位数字内容 ID（相邻章节的 URL 数字相差 2^32），而内容接口只按 ID 返回章节正文、不校验购买状态；攻击者从免费章节、下一章接口和听书接口补齐 ID 规律后，在 Burp Intruder 中以 `2^32 = 4294967296` 为步长累加数字 ID 爆破，即可批量取得付费章节的完整正文（MD5 风格 URL 只是预览接口，数字 ID 接口绕过付费墙）。

## 原理

- **打包 ID 的痕迹**：内容站常把 `bookId` 与 `chapterId` 打包成一个 URL 段（常见形式为 `chapter << 32 | book` 或类似组合），于是同书相邻章节的 URL 数字相差 `2^32`。案例中把连续两行章节 URL 的数字相减，得到的差都是 `4294967296 = 2^32`，说明数字的低/高 32 位分别承载不同字段，章节序号在高位递增。
- **为什么会越权**：章节内容接口按数字 ID 从存储取正文，只判断资源存在（或只校验登录），不校验当前用户是否购买/订阅了这本书；付费限制仅体现在前端隐藏入口与另一种 MD5 风格 URL 上。MD5 风格 URL 返回的是付费章节开头的预览片段，看似受限，但同一章节在数字 ID 接口上仍返回全文。
- **爆破步长**：如果按普通自增 `+1` 遍历，由于 ID 按 `2^32` 量化，命中率极低（案例中全是 404）；改用步长 `4294967296` 后，每个有效章节恰好命中一次，付费书的 5 个章节全部返回 200 与完整长度，随后 ID 越界变 404。
- **前端解密的角色**：正文在响应中是密文/乱码，页面有一个 JS 解密函数（案例在 Console 中调用 `KS(url)` 并先在解密函数下断点），把 URL 传给该函数即可得到明文。这说明「响应乱码」不等于不可利用——密文可以在浏览器运行时用站点自己的函数还原，无需完整逆向算法。
- **ID 空间的补齐**：需要三类接口配合：①接收 `bookId + chapterId` 返回下一章 `chapterId` 的接口；②返回首章 `chapterId` 的听书/目录接口；③`bookId` 可从页面或接口获得。三者齐备后即可生成全部章节的数字 URL，再做步长爆破。

## 触发条件

- 目标为小说、漫画、课程等付费内容站点，章节正文接口以数字 ID 为参数，且服务端只按 ID/登录态取内容，不校验购买授权。
- 数字 ID 可预测或可从免费章节/接口获得；相邻章节 ID 差为 2 的幂（案例为 `2^32`），可据此推断打包结构。
- 能访问到返回首章/下一章 ID 的辅助接口（免费章节列表、听书、目录等）。
- 正文被前端 JS 加密时，需要在浏览器 Console/断点中调用站点解密函数，或把密文交给页面 JS 处理。
- 爆破目标可承受一定量请求且无严格风控/限速；案例仅需 5 次有效请求即可取完付费书。

## 利用步骤

1. 打开任意免费章节，在 DevTools Network 中抓到 `https://novel-content.../<数字>` 形式的内容请求；响应为密文/乱码。
2. 在 Sources 中找到解密函数，在函数处下断点，Console 中调用 `KS("<完整 URL>")`，确认返回明文正文（函数名与调用方式随站点不同）。
3. 找辅助接口：抓「下一章」请求（参数 `bookId`、`chapterId`，返回 next `chapterId`）；翻「听书」功能找返回首章 `chapterId` 的接口；从页面/接口取 `bookId`。
4. 写脚本批量调用 `next` 接口，收集全部章节数字 ID 并拼成 URL 列表；打印相邻 ID，计算差值，确认步长为 `2^32`（案例脚本处理 1176 个章节）。
5. 对付费书：先记录一个「正常 URL」的数字部分，作为起始 payload。
6. Burp Intruder 选择数字参数为 payload 位置，payload 类型选 Numbers，From=起始 ID，Step=4294967296，To 设为起始 ID + 章节数 × 2^32；或用脚本生成 `start + n*4294967296`。
7. 按响应状态码/长度筛选 200 且长度较大的结果（案例 5 章长度分别约 446489、363208、305712、41022、25439 字节，其余 404 长度约 650）。
8. 对每个命中的密文响应调用站点解密函数（Console 循环或脚本），把明文保存为 txt；可用页面已有的 `download()`/Blob 方法批量下载，注意浏览器会提示多文件下载。
9. 核对下载内容是否包含「此章为付费章节」之后的全文，确认付费墙已被绕过。

## PoC

```javascript
// 1) 在站点 Console 中调用自带解密函数还原单章（先在该函数下断点）
KS("https://novel-content.<target>/<numeric-chapter-id>");
// Promise {<fulfilled>: "<解密后的章节明文>"}
```

```python
# 2) 按 2^32 步长生成爆破 payload（起始 ID 取自付费书正常 URL 的数字）
start = 6749011871265265967
step  = 1 << 32               # 4294967296
for n in range(0, 5):         # 案例该书共 5 章
    print(start + n * step)
```

```text
# 3) Burp Intruder 配置
Payload type : Numbers
From         : <start>        # 正常 URL 的数字
Step         : 4294967296     # 2^32
To           : <start + N*step>
# 命中判据：Status 200 且 Length 远大于预览页；案例 5 个 200 后全部 404
```

案例在真实小说站完成并成功下载付费章节全文（截图显示下载得到的 `data(1..4).txt` 与 `data.txt` 含完整章节）。数字打包结构（哪 32 位是章节）与解密函数名因站而异，本卡按观察到的 `2^32` 差值描述；未在本机复跑。

## 变体与关联

- 关联：[[web-generic-auth-course-id-enumeration-courseware-url]]、[[web-generic-auth-idor-current-path-replacement-sibling-crud]]（自增/可预测对象 ID 的 IDOR 遍历，ID 编码与目标不同）。
- 关联：[[web-generic-auth-vip-course-direct-media-url-leak]]、[[web-generic-auth-frontend-media-direct-url-plain-download]]（付费/会员内容的其它绕过形态：直链未鉴权；本卡是按 ID 取正文的接口越权）。
- 关联：[[tools-burp-autodecoder-flask-sekiro-jsrpc-body-encrypt-decrypt]]、[[code-analysis-reverse-obfuscation-js-config-array-console-aes-key-iv]]（前端加密流量的运行时解密与自动化，本卡只复用「调用站点解密函数」的思想）。
- 变体：打包位宽不一定是 32 位，也可能是 2^16/2^48；先从两个已确认章节的 ID 差值推断，再验证步长命中率。
- 变体：若数字接口需要登录，用低权账号即可；若数字 URL 被下线，历史接口、听书接口、旧版 API 常仍按数字 ID 返回全文。
- 边界：服务端若在数字接口上也校验购买，则爆破只返回预览/错误；步长假设错误会全是 404；前端加密+强风控会显著提高批量获取成本；付费内容存在版权与合规边界，测试应获得授权。

## 检测与防御

- **授权**：每个章节请求都做对象级授权（校验用户已购买/订阅该书），不要以「ID 存在」「已登录」代替；预览接口与全文接口在后端强制分离。
- **ID 设计**：不要用可预测的打包自增 ID 暴露内容；使用随机 UUID/带用户绑定的签名 URL，签名含过期时间与用户标识。
- **监控**：短时间内对内容接口的大批量数字请求、规律步长（同一增量反复出现）、大量 200/404 混合与异常下载量；对单账号/单 IP 做速率限制与行为分析。
- **前端加密的定位**：前端加密/解密只防普通抓包，不构成授权；安全评审应把解密函数同时视为攻击者工具。
- **响应**：发现越权下载时下线相关接口、修复授权判断、评估泄露内容范围并按业务要求取证。
