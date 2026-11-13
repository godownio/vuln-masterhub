---
id: ctf-misc-lora-gr-lora-signal-decoding
title: LoRa 原始采样解码：频谱估中心频率/带宽、采样率与带宽整数倍、SF 6-12 试解，gr-lora LoRa Receiver 流程与 WAV→complex64 转换
type: scenario
domain: ctf
path: ctf/misc
technique: lora-gr-lora-iq-signal-decoding
tags:
- ctf
- misc
- lora
- sdr
- gnuradio
- gr-lora
- signal-decoding
- iq
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V550
  verified_at: '2026-11-11T22:50:28+08:00'
  notes: '已对照原文与全部23张图核对：图01 LoRa Receiver 原始参数 Sample rate 375000/Center 500788875/BW 125000/SF8；图05 频谱 500.512.5 MHz BW 375kHz；图07 修正后 Center/Channel 500500500；图10 CyberChef 解出 N1pWelcome, Be A RWCTFer! rwctf{Gr33t_Fr0m_LoR4_...}；图11 WAV File Source 报 RuntimeError: not a valid wav file；图12 文件名 486_375MHz-1MSps-1MHz；图13 频谱中心约 375M；图14 流程图 File Source(complex64)→Throttle 1M→LoRa Receiver(SR 1M/Center 375M/BW 250k/SF11)；图15 LoRa 包结构 Preamble/Header/CRC/Payload。已按截图核对卡内参数与 scipy complex64 脚本，并对 raw 帧数据做了去前3字节+后2字节的抽取一致性检查（如 68 30 60 ff ff ff ff... → ffffffff c4c06dfa...）。修正两处表述：① 文件名提示中 ''带宽 1 MHz 段'' 改为采样带宽 1 MHz 且实际信号 BW 约 250k（避免误设 BW=1MHz）；② ''CBR 与 SF 组合决定符号率'' 改为 Rs=BW/2^SF、CR 影响载荷时长。dedup：top 候选为 NBFM Morse、WAV 8FSK、SSTV、音频单频 FFT 等不同解调方式，无同链；dup-scan.json 未涉及本卡。原文未标注软件版本，affected_versions 保持空。未验证点：未在 GNU Radio 环境实际重跑解调（仅按截图核参）。'
url: /docs/ctf/misc/ctf-misc-lora-gr-lora-signal-decoding/
draft: false
kb_aliases:
- LoRa 信号解码
- gr-lora
- GNU Radio LoRa Receiver
- LoRa 采样率 带宽 扩频因子
- LongRange1
- complex64 IQ 转换
---

## 一句话结论

拿到 LoRa 的 WAV/复数采样（IQ）后，用 gr-lora 的 `LoRa Receiver` 模块解调：从频谱图估算中心频率与带宽，令采样率大于等于带宽 2 倍且为整数倍，扩频因子（SF）在 6–12 间按输出是否可读试解；GNU Radio 流程为 `File/Wav Source → Float To Complex → Throttle → LoRa Receiver`，WAV 源报错时用 scipy 把立体声转成 `complex64` 裸文件再用 `File Source` 读取。

## 原理

- **LoRa 物理层参数**：LoRa 用 CSS（Chirp Spread Spectrum）扩频，接收端需要匹配中心频率、带宽（BW）、扩频因子（SF）与采样率。SF 表示每个信息位用多少个 chirp 符号表示（SF=6→64 chips/symbol，SF=12→4096），SF 越高解调所需 SNR 越低（示例表：SF6 -5 dB 到 SF12 -20 dB），但速率越低。
- **采样率与带宽关系**：带宽是信号占据的频宽，采样率需满足奈奎斯特（≥2×带宽），实际 SDR 采样常取带宽的整数倍；示例中 BW=125 kHz、采样率 375 kHz（3 倍），第二题 BW=250 kHz、采样率 1 MHz（4 倍）。
- **中心频率估计**：题面给的中心频率可能不在信号中心（示例标称 500.5125 MHz，频谱上信号中心约 500.5005 MHz），要用频谱仪/瀑布图的 -3 dB 半功率点确定实际中心与带宽，或从文件名（如 `486_375MHz-1MSps-1MHz` → 中心 375 MHz、采样率 1 MSps、采样带宽 1 MHz，信号实际 BW 约 250k，需频谱确认）读取提示。
- **gr-lora 流程**：`Wav File Source`（或 `File Source` 读 complex64）→ `Float To Complex`（WAV 为实数采样时）→ `Throttle`（限制处理速率，避免 CPU 打满）→ `LoRa Receiver`（配置 Sample rate/Center frequency/Channel list/Bandwidth/Spreading factor/Implicit header）。解调输出为字节流，前导码/帧头/CRC 之后是有效载荷。
- **WAV 源兼容问题**：容器里 GNU Radio 的 `wavfilesource` 可能报 `RuntimeError: not a valid wav file`；用 scipy 读出双声道后合成复数 `data[:,0] + 1j*data[:,1]`，归一化为 complex64 写裸文件，再用 `File Source` 即可绕过。

## 触发条件

- 获得 LoRa 信号的 WAV 或 complex64/IQ 采样文件（CTF 附件、SDR 抓包），频谱上可见 125/250/500 kHz 量级的宽带信号。
- 有 GNU Radio + gr-lora 环境（官方提供 Docker，`docker_run_grlora.sh` 启动后可用 `gnuradio-companion`）。
- 已知或可估计中心频率、带宽与采样率的整数倍关系，SF 未知时需枚举。

## 利用步骤

1. 用频谱工具（SDR#、inspectrum、GNU Radio QT GUI）查看采样文件，估出信号中心频率与 -3 dB 带宽；核对采样率是否为带宽的整数倍且 ≥2 倍。
2. 若源为 WAV，按双声道 I/Q 转 complex64：
   ```python
   from scipy.io import wavfile
   import numpy as np
   samplerate, data = wavfile.read('./capture.wav')
   signal = (data[:,0] + data[:,1] * 1j).astype(np.complex64)
   signal /= (2**32)//2
   signal.tofile('./capture.complex64')
   ```
3. 在 GNU Radio 搭建流程：`File Source`（读 complex64）→ `Throttle`（Sample Rate 设为文件采样率）→ `LoRa Receiver`。
4. 配置 LoRa Receiver：Sample rate=文件采样率，Center frequency=频谱中心，Channel list=同中心频率（或标准信道），Bandwidth=估计带宽，Implicit header=No，SF 从 6 到 12 逐一尝试，直到输出字节流出现可读 ASCII/预期结构。
5. 保存解调输出的十六进制字节流；按 LoRa 包结构去掉前导/帧头/CRC（示例中去掉前 3 字节与后 2 字节），得到有效载荷。若载荷是 Meshtastic 等协议报文，继续做协议层解析/解密。

## PoC

GNU Radio 参数示例（LongRange1，解出明文 flag）：

```text
Sample rate:        375000
Center frequency:   500500500      # 题面 500.5125 MHz，按频谱修正
Channel list:       500500500
Bandwidth:          125000
Spreading factor:   8
Implicit header:    No
Decimation:         1
```

LongRange2（文件名 `486_375MHz-1MSps-1MHz`）：

```text
File Source:        capture.complex64
Sample rate:        1M
Throttle:           1M
Center frequency:   375M
Channel list:       375M
Bandwidth:          250k
Spreading factor:   11
```

解调输出（LongRange1）示例：

```text
4e 31 70 57 65 6c 63 6f 6d 65 2c 20 42 65 20 41 20 52 57 43 54 46 65 72 21 ...
# ASCII: N1pWelcome, Be A RWCTFer! rwctf{...}
```

## 变体与关联

- 变体：SF 未知时用循环脚本批量跑 6–12，按输出字节的可打印率/协议结构自动判定正确 SF；带宽未知时按标准值 125/250/500 kHz 枚举。
- 变体：符号率由带宽与 SF 决定（Rs=BW/2^SF），编码率 CR 影响载荷时长；gr-lora 的 `Implicit header` 在无显式帧头的信号上需要设为 Yes。
- 变体：除 gr-lora 外，可用 `inspectrum` 看 chirp、`lora-phy`/`gr-lora_sdr` 等其他解调实现；核心都是中心频率+BW+SF+采样率四参数匹配。
- 关联：[[ctf-misc-meshtastic-aes-ctr-flashdump-key-decrypt]]（本链解出的 Meshtastic 报文如何用 flash dump 中的 channel key 解密）、[[ctf-forensics-wav-multifrequency-8bit-block-fsk-stego]]（另一类音频信号解调）。
- 边界：采样率不足/中心频率偏差大会导致解调失败；WAV 需为 I/Q 双声道而非单声道音频；重采样或削波会破坏 chirp 线性度。

## 检测与防御

- 无线电安全视角：LoRa 物理层本身不加密，任何能收到信号的人都可以解调；业务方应在应用层加密（如 Meshtastic 的 AES-CTR）并保护密钥。
- 防御：敏感数据不通过公开 LoRa 信道明文传输；使用私有信道密钥并定期轮换；对设备 flash 做读保护，避免密钥被 dump。
- 检测：频谱监测发现异常 LoRa 信号（非授权频段/功率）可作为射频侧排查线索。
