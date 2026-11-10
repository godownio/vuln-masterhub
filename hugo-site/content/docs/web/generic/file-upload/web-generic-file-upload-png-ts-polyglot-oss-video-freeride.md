---
id: web-generic-file-upload-png-ts-polyglot-oss-video-freeride
title: PNG 头 + MPEG-TS 拼接 polyglot 伪装图片绕过上传校验并盗用 OSS 视频流量
type: scenario
domain: web
path: web/generic/file-upload
technique: png-mpegts-polyglot-upload-bypass
tags:
- 文件上传
- 图片马
- polyglot
- PNG
- MPEG-TS
- 内容校验绕过
- OSS
- dplayer
- 资源盗用
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-2
  verified_at: '2026-11-07T21:50:18+08:00'
  notes: 已对照原文核对；PNG IHDR头与MPEG_TS标记共存经010Editor分析(图14-16)、123.ts可播放(图18)、黑产真实使用(正文第68与100行)证实，PoC结构示意与原理一致；dedup_review对比image-zip-polyglot-symlink-read(ZIP软链接读flag)、magic-byte-gif-prefix-bypass(PHP getshell)、imageio-polyglot(XSS)、png-iend-appended-webshell成立，本卡payload为MPEG-TS且利用TS可从任意包边界解析、目标为OSS免费视频CDN，非同一利用链；排除判断：主危害为绕过只校验文件头的上传内容检测，非DoS崩溃或仅资源耗尽、非未打通理论链，刷量计费资金损失已由worker作为独立场景排除未成卡；confidence为medium因作者明确不能通过刷量验证危害、未亲自复现上传绕过加持续刷流量完整链，该限制已在正文说明；未验证点：PoC为结构示意未运行
url: /docs/web/generic/file-upload/web-generic-file-upload-png-ts-polyglot-oss-video-freeride/
draft: false
kb_aliases:
- PNG 头伪装视频
- IHDR + MPEG_TS
- 图片头拼接 ts 流
- dplayer 白嫖 OSS
- 多语义文件绕过上传校验
---

## 一句话结论

把一个合法的 PNG 文件头（含 IHDR）拼在 MPEG-TS 视频流前面，构成头部看起来是图片、尾部却是完整 TS 流的 polyglot 文件；只校验文件头魔数/图片头的上传点会把它当图片放行，而播放器从 `MPEG_TS` / TS 包边界开始读取即可正常播放，从而在目标企业 OSS 存储桶里存放盗版视频并盗用其流量与带宽。

## 原理

- 很多上传校验只读前几个字节的魔数或用图片库解析文件头：`89 50 4E 47 0D 0A 1A 0A`（PNG 签名）+ `IHDR` 块存在即判定为合法图片，不检查文件尾部是否夹带其他数据。
- MPEG-TS 是"连续输出、恒定包长（188 字节）的传输流"，其设计允许从流的任一片段/任意包边界开始解析（原文引述的 TS 格式解析特性）；因此在 TS 数据前加任意前缀字节并不破坏后续 TS 包的解析，播放器跳过前缀、从 `MPEG_TS` 标记或首个同步字节 `0x47` 起读即可播放。
- 二者结合：文件头满足"图片"校验、文件尾满足"视频"播放，形成多语义（polyglot）文件。原文用 010Editor 在真实黑产文件中同时看到 PNG `IHDR` 与 `MPEG_TS` 标记，且把该文件改名 `123.ts` 后能正常播放出画面。
- 危害链：黑产先在大厂业务找任意文件上传漏洞 → 把盗版 mp4 切成 m3u8/ts 分片并在片头加 PNG 头 → 上传到企业 OSS 拿到存储地址 → 盗版站前端用 dplayer/HLS 播放器加载该地址 → 所有存储与下行流量费都记到企业账单（原文称单月可达数十万），同时因文件头是图片而绕过了安全设备的内容检测。

## 触发条件

- 目标存在任意文件上传点，且校验只依赖文件头魔数/图片头（不校验尾部、不重编码、不按完整格式解析）。
- 上传点最终落到按量计费的对象存储（OSS/COS/S3）或 CDN，且资源可被公网读取播放。
- 前端播放器（dplayer、HLS/m3u8 等）能按 URL 加载并容忍文件头前缀。
- 存储桶 ACL 为公共读或存在长期有效的可读 URL（私有 + 短时效签名 URL 会阻断）。

## 利用步骤

1. 把视频切成 TS 分片（m3u8 + ts），保留 `MPEG_TS` / TS 同步字节结构。
2. 在每个分片前拼接一段最小合法 PNG 头（PNG 签名 + IHDR 块），使文件前若干字节完全符合 PNG 规范。
3. 通过任意文件上传点上传，确认因"看起来是图片"被放行，取得返回的 OSS 对象地址。
4. 在盗版站用 dplayer 配 m3u8/ts 地址播放；播放器从 TS 偏移处起读，正常出画面。
5. 大量用户播放即持续消耗企业 OSS 下行流量与请求费用（若上传黄暴内容还可制造合规风险）。

## PoC

```text
# 构造：PNG 头 + TS 分片（结构示意，未执行）
PNG 签名: 89 50 4E 47 0D 0A 1A 0A
IHDR 块:  00 00 00 0D 49 48 44 52 ...   # 合法 PNG 头，能通过图片校验
<随后直接拼接 MPEG-TS 分片数据，含 MPEG_TS 标记 / 0x47 同步字节>

# 上传后把返回地址交给播放器
<video src="https://target.oss.example/.../clip.ts">   # dplayer/HLS 从 TS 偏移起读，正常播放
```

（原文已用 010Editor 验证同一文件同时含 IHDR 与 MPEG_TS，并实测 `123.ts` 可播放；本节为结构示意，未运行任何 PoC。）

## 变体与关联

- 变体：把 PNG 换成 GIF89a/JPG 头、把 TS 换成 MP4/flv，只要"头校验"与"播放器容错"成立即可。
- 变体：同类 polyglot 还有"图片头 + ZIP 软链接解压读文件""GIF89a 前缀夹带 PHP 代码"等，本场景差异在 payload 是视频流、利用的是 TS 可任意偏移解析、目标是盗用云存储流量而非 getshell/读 flag。
- 关联：与"对象存储 Bucket ACL 公共读配置错误"链式使用——后者提供公网可读，本场景提供能过校验的视频载荷。
- 关联：与"VIP 课程/付费媒体直链泄露"同属把企业付费资源当免费 CDN 的业务风险。
- 关联：confidence 标 medium——文件结构与可播放性原文已验证、黑产真实使用，但作者未亲自复现"上传绕过 + 持续刷流量"的完整链，且危害依赖目标 OSS 计费与 ACL 配置。

## 检测与防御

- 检测：上传文件头是图片但在偏移处出现 `MPEG_TS`、`0x47` TS 同步字节、m3u8 或其他非图片结构；对象存储出现大量大体积"图片"被以视频 Range 方式高频读取；账单下行流量/请求数异常突增。
- 防御：上传校验不能只看文件头，需按声明格式做完整解析/重编码（图片二次渲染、视频转码），拒绝尾部夹带数据；对对象与 Content-Type 做一致性校验。
- 防御：Bucket ACL 设为私有，只用服务端动态生成、带 `sign`/`Expires` 短时效的签名 URL；配合 Referer/IP 防盗链、WAF/OSS 高防与流量告警、账单阈值与用量上限。
- 防御：限制单对象大小与上传类型，隔离用户上传与静态资源域名；对异常流量做自动熔断（避免高额账单）。
