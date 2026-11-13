---
id: defense-detection-video-file-canarytoken-rdrf
title: 视频文件 Canarytoken：在 .mov/.mp4 的 moov>rmra>rmda>rdrf 原子写入外部 URL，VLC 打开即触发 DNS/HTTP 告警
type: scenario
domain: defense
path: defense/detection
technique: video-file-canarytoken-rdrf-atom
aliases:
- 视频文件蜜标
- rdrf 原子蜜罐
- QuickTime 参考影片令牌
- mov Canarytoken
- 文件型 Canarytokens
tags:
- defense
- detection
- canarytoken
- honeytoken
- quicktime
- mov
- mp4
- vlc
- file-format
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V549
  verified_at: '2026-11-11T22:06:21+08:00'
  notes: 已对照原文(xz 13096)与5张截图复核：moov>rmra>rmda>rdrf 原子树与URL存储、双rdrf（外部+本地）必要性、VLC触发DNS/HTTP且将多rdrf按播放列表、.mp4同样有效、WMP忽略rdrf、QuickTime 10.5加rmda后拒绝打开而Quick Look可播放、QuickTime 7可触发、dref被VLC/QuickTime忽略，均与原文及MP4Analyser/VLC告警截图一致。验证中修正：删除'ffprobe/文件解析器/十六进制查看器打开不会触发'的绝对化推断，改为纯静态查看不请求URL、ffprobe等依实现而定（原文未测试）。PoC为按原子结构整理的最小示意并注明原文无完整脚本、未执行。frontmatter无sources/source_url/文章ID/URL，cve []，无affected_versions，path defense/detection合法；dedup仅命中自身，与既有honeytoken/检测卡不同链。
---

## 一句话结论

QuickTime `.mov` 容器允许在 `moov > rmra > rmda > rdrf` 原子中写入“参考影片”的外部 URL；给一个正常视频文件追加指向自己服务器的 `rdrf` 原子后，攻击者用 VLC 打开该文件就会自动发起 DNS/HTTP 请求，从而把视频文件变成可告警的文件型 Canarytoken；同一结构对 `.mp4` 也生效，但 Windows Media Player 与新版 QuickTime 不会按同样方式触发。

## 原理

- **文件型 Canarytoken 的共性**：在文件中嵌入外部 URL，依赖阅读器/播放器打开文件时主动访问该 URL（哪怕只是 DNS 解析），从而在攻击者接触文件时告警；假 Excel/PDF、带 CRL URL 的签名程序都是同一思路。
- **QuickTime 容器结构**：`.mov` 由“原子”（atom）树组成，每个原子有类型与长度，可嵌套。`moov` 是描述影片元数据的父原子；引用外部影片时使用 `rmra`（reference movie atom），其下 `rmda`（reference movie data atom）再到 `rdrf`（reference movie data reference atom），URL 就存储在 `rdrf` 中。
- **VLC 的行为**：VLC 解析到 `rdrf` 的外部 URL 时会发起 DNS 与 HTTP 请求。若 `rdrf` 指向的 URL 无法解析，VLC 不会回退到文件内本地媒体数据，因此需要同时保留一个指向本地文件的 `rdrf`；多个 `rdrf` 会被 VLC 当作播放列表依次处理。给已有 `.mov` 追加“一条外部 URL + 一条本地文件”的 `rdrf`，即可在保留可播放性的同时触发告警。
- **兼容性**：由于 `.mov` 与 `.mp4` 结构相近，同一改法对 `.mp4` 也有效；但 Windows Media Player 完全忽略 `rdrf` 只播放本地媒体，QuickTime 10.5 在加入 `rmda` 后直接拒绝打开（Quick Look 仍可播放本地数据），旧版 QuickTime 7 可触发。`dref` 原子里的 URL 则被 VLC 与 QuickTime 同时忽略。
- **为什么适合做蜜标**：攻击者在内网看到“Zoom 录音/董事会录像/媒体公司素材”这类文件，很可能用 VLC 打开；一旦打开就命中外部 URL，告警可附带源 IP 与时间。文章最终因“只在 VLC 稳定触发”未把它做成官方产品，但结构本身可作为自建蜜标。
- **边界**：触发依赖播放器与版本；不联网或禁止出站 DNS/HTTP 的环境不会告警；纯静态查看（十六进制编辑器、文件解析器）不会主动请求 URL，`ffprobe` 等工具是否跟随参考影片依实现而定（原文未测试）；文件需要看起来真实（保留可播放的本地媒体与合理文件名）。

## 触发条件

- 防守方能把构造好的 `.mov`/`.mp4` 投放到攻击者可能翻找的位置（文件服务器、共享目录、终端、云盘等）。
- 攻击者使用 VLC（或旧版 QuickTime 7）打开该文件，且主机允许对外 DNS/HTTP。
- `rdrf` 指向的域名/URL 由防守方控制并能记录请求（HTTP 服务、DNS 日志或 Canarytokens 类服务）。
- 文件保留至少一个可解析的本地 `rdrf` 或本地媒体数据，避免播放器因外部 URL 失败而完全不播放。

## 利用步骤

> 以下为防守方制作与部署步骤。

1. 准备一个正常、可播放的 `.mov`（或 `.mp4`）视频，文件名与投放场景匹配（如会议录像、产品素材）。
2. 用脚本/十六进制编辑器在 `moov` 下加入 `rmra > rmda > rdrf`，`rdrf` 写入指向自己服务器的 URL；再保留/添加一个指向本地媒体文件的 `rdrf`。
3. 用 MP4 原子分析工具检查树结构，确认 `moov>rmra>rmda>rdrf` 顺序与长度字段正确。
4. 在测试机用 VLC 打开，确认产生 DNS/HTTP 请求且视频仍可播放；用 Windows Media Player 与新版 QuickTime 验证兼容性差异。
5. 把文件投放到诱饵位置，监控 URL 的 DNS/HTTP 命中；命中后记录源 IP、时间与访问路径并联动告警。
6. 定期更换 URL/文件名，避免攻击者凭已知域名识别蜜标。

## PoC

```text
# 原子树结构（示意）
moov
├── mvhd
└── rmra
    └── rmda
        ├── rdrf  -> http://<token-domain>/<token-id>/video.mov   # 外部 URL：触发告警
        └── rdrf  -> ./local-video.mov                            # 本地引用：保证可播放
```

```python
# 伪代码：在已有 mov 的 moov 中追加 rmra/rmda/rdrf 原子
def atom(kind, payload):
    return struct.pack(">I", 8 + len(payload)) + kind + payload

external = atom(b"rdrf", b"http://<token-domain>/<token-id>/video.mov\x00")
local    = atom(b"rdrf", b"./local-video.mov\x00")
rmda     = atom(b"rmda", external + local)
rmra     = atom(b"rmra", rmda)
mov      = insert_child(mov, parent=b"moov", child=rmra)  # 需同步更新各级长度
```

说明：文章未给出完整脚本，只描述了用十六进制编辑器与参考文件试验的过程；上述为按原子结构整理的最小示意，未在真实样本上执行。

## 变体与关联

- **其他文件型蜜标**：假 Excel/PDF 内嵌远程资源、签名 EXE 的 CRL URL、Office 文档外部模板等；与视频 `rdrf` 同属“阅读器主动访问外部 URL”的原语。
- **CSS/JavaScript 克隆站蜜标**：用于检测 AitM 钓鱼页面，见 [[defense-detection-css-clone-site-canarytoken-aitm]]；视频蜜标用于内网文件接触检测。
- **变体**：只放 `rdrf` 不给本地媒体可做“纯引用影片”，但兼容性更差；也可用 `dref` 尝试，但 VLC/QuickTime 均忽略。
- **边界**：VLC 版本差异、播放器不解析参考影片、出站被阻断都会导致漏报；蜜标只告警不阻断。

## 检测与防御

- **部署侧**：把视频蜜标放在攻击者高概率翻找的目录，文件名贴合业务；记录 URL 与投放位置，定期轮换。
- **告警侧**：对蜜标域名的 DNS/HTTP 请求做告警与源 IP 画像；结合终端进程（vlc.exe）与文件访问日志确认是人为打开而非扫描器解析。
- **防御纵深**：限制内网到未知域名的出站；对共享目录中的媒体文件做来源与完整性校验；红队/紫队演练可把此类蜜标纳入暴露面检查。
- **识别蜜标（攻击者视角）**：检查 `moov` 下是否存在异常 `rmra/rmda/rdrf` 外部 URL、文件是否缺少本地媒体却体积正常；纯静态查看不会主动请求 URL，不能只靠静态查看判断是否已触发（`ffprobe` 等解析工具行为依实现而定，原文未测试）。
