---
id: ctf-forensics-video-corpus-frame-ocr-vlm-flag-search
title: 海量视频语料中检索隐藏 flag：发布时间排序 + 逐帧 OCR/VLM 扫描
type: scenario
domain: ctf
path: ctf/forensics
technique: video-corpus-frame-ocr-vlm-flag-search
aliases:
- FLAG LEAK
- 视频抽帧 OCR
- YouTube 元数据排序
- LLaVA 视觉检索
- 逐帧文本提取
- AICTF 2025
tags:
- ctf
- forensics
- video
- ocr
- vlm
- osint
- yt-dlp
- tesseract
- llava
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:27:01+08:00'
  notes: 已对照原文与图11-15核对：1000视频、yt-dlp按upload_date倒序、1fps抽帧、Tesseract/LLaVA两条管线、311秒帧命中FLAG_sXJMBmqcAN5X；人工查看最新视频亦命中；dedup候选为视频像素隐写/SIXEL等不同载体
---

## 一句话结论

当 flag 只出现在 1000 个随机视频中的某一帧画面里时，先用 `yt-dlp` 批量取视频元数据并按发布时间倒序排列（主办方新上传的目标视频通常排在最前），再以 1 fps 抽帧、灰度/自适应阈值增强后跑 Tesseract OCR，或用 LLaVA 等视觉语言模型逐帧询问“是否出现 FLAG_ 开头的文本”，即可从海量视频中定位并还原 flag；原文用元数据排序 + 人工查看最新视频在 311 秒处找到 `FLAG_sXJMBmqcAN5X`，OCR 与 VLM 管线也能自动命中。

## 原理

- **信息不在元数据**：flag 被画在视频画面里，标题/描述/字幕通常没有；必须“看”画面。
- **发布时间是强先验**：1000 个视频多为陈旧随机内容，CTF 主办方制作的含 flag 视频发布时间接近比赛日期；按 `upload_date` 倒序后目标大概率在列表最前，人工只需检查少量视频。
- **抽帧检索**：以固定间隔（如 1 秒）抽帧，把视频检索降维成图片文本检索；flag 至少持续若干帧，1 fps 足够覆盖。
- **OCR 管线**：灰度化 + 自适应阈值 + 放大可提升小字/低对比度文字的识别率；OCR 结果做 `F L A G _` → `FLAG_` 等归一化后正则匹配。
- **VLM 管线**：视觉语言模型能结合上下文识别风格化文字/噪声画面，比传统 OCR 更鲁棒，但速度/成本更高；给模型的提示要明确“只提取 FLAG_ 开头的文本，否则回复未找到”。
- **为什么可行**：视频是图像序列，flag 是画面中的文本；只要枚举帧并做文本识别，就能把“找视频”变成“找字符串”。

## 触发条件

- 拿到一个视频集合（链接列表/下载地址），其中某个视频包含目标文本。
- 视频可下载、可解码（yt-dlp/ffmpeg/OpenCV）。
- 目标文本有固定前缀（如 `FLAG_`）或规则，便于 OCR/VLM 匹配。
- 若平台有反爬/访问限制，需要延迟、重试、代理或缓存元数据。

## 利用步骤

1. 从挑战页面抓取所有视频链接；用 `yt-dlp --skip-download` 批量取标题、`upload_date`、视频 ID，写入 CSV。
2. 按发布日期倒序排序，优先检查接近比赛时间/最新上传的视频。
3. 对候选视频以 1 秒间隔抽帧（OpenCV `CAP_PROP_POS_FRAMES`）。
4. OCR 路线：每帧转灰度、自适应阈值、放大后送 Tesseract；对结果做空格归一化并正则 `FLAG_[A-Za-z0-9_]+`。
5. VLM 路线：把每帧送 LLaVA/GPT-4V 等，提示“若出现 FLAG_ 开头的文本请精确提取，否则回复未找到”，命中即停止。
6. 人工复核命中帧，确认字符（OCR 可能把 `1`/`l`、`0`/`O` 混淆），提交 flag。

## PoC

```python
import yt_dlp, cv2, re, pytesseract
from datetime import datetime

def meta(url):
    with yt_dlp.YoutubeDL({'quiet': True, 'skip_download': True}) as ydl:
        info = ydl.extract_info(url, download=False)
    return {'url': url, 'id': info['id'], 'title': info.get('title'),
            'date': datetime.strptime(info['upload_date'], '%Y%m%d')}

videos = sorted([meta(u) for u in open('video_urls.txt').read().split()],
                key=lambda v: v['date'], reverse=True)

def scan(video):
    ydl_opts = {'quiet': True, 'format': 'mp4[height<=360]',
                'outtmpl': f"{video['id']}.%(ext)s"}
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        ydl.download([video['url']])
    cap = cv2.VideoCapture(f"{video['id']}.mp4")
    fps = cap.get(cv2.CAP_PROP_FPS)
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    for sec in range(0, int(total / fps)):
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(fps * sec))
        ok, frame = cap.read()
        if not ok:
            continue
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        text = pytesseract.image_to_string(gray).replace(' ', '')
        m = re.search(r'FLAG_[A-Za-z0-9_]+', text)
        if m:
            return m.group(), sec
    return None, None
```

VLM 版本把 `pytesseract` 换成 LLaVA/GPT-4V 的图片问答即可。原文 OCR 日志在 311 秒帧命中 `FLAG_sXJMBmqcAN5X`。

## 变体与关联

- **平台变体**：B 站/抖音/自建视频站；元数据字段不同，抽帧与 OCR 不变。
- **载体变体**：flag 在音频（Whisper 转写）、字幕、弹幕、缩略图、视频元数据；可先用 `ffprobe`/字幕文件缩小范围。
- **优化**：先做场景切换/关键帧检测减少帧数；对 OCR 结果做多帧投票；对大语料并行下载/抽帧。
- **关联**：[[ctf-forensics-video-single-pixel-channel-extraction]]（视频像素隐写）、[[ctf-forensics-sstv-audio-image-decode]]（音频转图像）、[[ctf-misc-osint-cross-platform-username-steam-former-name]]（OSINT 检索思路）。

## 检测与防御

- 本卡是 CTF/取证检索方法；对防守方的启示：不要把敏感信息仅以画面文字形式放在公开视频中，发布前做帧级 OCR/敏感信息扫描；视频平台可对上传内容做文字审核。
- 对检索方：注意平台访问频率限制与版权/隐私边界，只处理授权/比赛提供的数据。
