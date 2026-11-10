# CTF Misc

## 这层是什么

Misc/杂项技巧。

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
| [3D Gaussian 点云栅格化：z 分层连通分量 + 二维格点拟合还原像素排列，球谐系数邻域一致性提取文字](ctf-misc-3dgs-point-cloud-lattice-rasterization.md) | verified | high | 2026-11-06 |
| [AD1 镜像批量文件时间戳分钟位二进制：两值映射为 0/1 还原 Encrypto 密码](ctf-misc-ad1-file-mtime-minute-parity-binary-encrypto.md) | verified | medium | 2026-11-08 |
| [APNG fcTL delay_num 隐写：帧延迟数值按 ASCII 编码隐藏信息](ctf-misc-apng-fctl-delay-num-ascii-stego.md) | verified | high | 2026-11-07 |
| [base64 隐写（等号位/填充比特）：按组取未用低位比特拼流还原隐藏数据](ctf-misc-base64-padding-bit-stego-recover.md) | verified | medium | 2026-11-08 |
| [Bash 算术数组下标注入 + sleep 计时盲读：正则缺 $ 与 let 十六进制前缀绕过](ctf-misc-bash-arithmetic-array-index-sleep-blind.md) | verified | high | 2026-11-06 |
| [BlackBasta 勒索文件解密：No More Ransom 解密器 + decryptblocks.py 修补 flags 字段与 SRL_IGNORE_MAGIC](ctf-misc-blackbasta-decryptor-decryptblocks-patch.md) | verified | medium | 2026-11-08 |
| [BMP 文件头尺寸字段篡改修复：按像素数据长度重算 biWidth/biHeight 显示被裁掉的隐藏图像](ctf-misc-bmp-header-size-repair.md) | verified | medium | 2026-11-07 |
| [CRC32 四字节原像：GF(2) 线性矩阵求逆从已知 CRC 还原 ZIP 未知内容](ctf-misc-crc32-four-byte-preimage-gf2-linear.md) | verified | high | 2026-11-06 |
| [CS 皮肤模板编号隐写：同皮肤花纹差异对应模板号，按图序转 ASCII](ctf-misc-cs-skin-pattern-seed-ascii.md) | verified | high | 2026-11-06 |
| [Excel 神经网络权重逆向：ReLU 双神经元比较对恢复目标输入字符](ctf-misc-excel-neural-network-weight-reversal.md) | verified | high | 2026-11-06 |
| [Excel 黑盒确定性加密函数还原：构造已知输入输出对照表拟合多项式再解析求逆](ctf-misc-xlsx-chosen-plaintext-blackbox-function-recovery.md) | verified | high | 2026-11-08 |
| [Gerber PCB 层提取：在线查看器逐层剥离内层铜箔读取隐藏 flag](ctf-misc-gerber-pcb-layer-flag-extraction.md) | verified | high | 2026-11-07 |
| [GIF 多帧二维码批量提取：分帧排序、pyzbar/OpenCV 双解码与 base64 片段拼接](ctf-misc-gif-frames-qr-batch-scan-base64-join.md) | verified | high | 2026-11-07 |
| [GIF 帧间隔隐写：延迟时间按 10ms 单位编码 ASCII/二进制](ctf-misc-gif-frame-duration-ascii-stego.md) | verified | high | 2026-11-06 |
| [GPX 轨迹异常点定位：按相邻 trkpt 距离找离群点，读取其 time 作为 flag](ctf-misc-gpx-track-outlier-nearby-coordinate-time.md) | verified | medium | 2026-11-07 |
| [IBM Selectric 字球卡死编码：T1/T2 倾斜位与旋转列还原乱序记录](ctf-misc-selectric-typeball-tilt-rotation.md) | verified | high | 2026-11-06 |
| [JPEG SilentEye + WAV 内嵌 ELF + AES-128-ECB 脏串包裹：多层 Misc 提取与解密](ctf-misc-silenteye-wav-elf-aes-ecb-dirty-wrapper.md) | verified | high | 2026-11-06 |
| [JPEG 尾部 Base64 01 串 + EXIF 备注口令 steghide 提取：伪加密 ZIP 修复与 ELF 逐位 XOR 求压缩包口令](ctf-misc-jpeg-steghide-exif-elf-xor-pseudo-zip.md) | verified | high | 2026-11-07 |
| [JPEG 段与 EXIF/COM/DQT 元数据隐写：遍历 marker 提取隐藏片段](ctf-misc-jpeg-segment-metadata-stego.md) | verified | high | 2026-11-06 |
| [Keras/HDF5 模型权重隐写：异常层名 kernel 乘 1000 还原 ASCII](ctf-misc-hdf5-keras-weight-ascii-hidden.md) | verified | high | 2026-11-06 |
| [OSINT 作品溯源：从音乐/影视数据库到创作者讣告与纪念页](ctf-misc-osint-work-provenance-creator-obituary-memorial.md) | verified | high | 2026-11-06 |
| [OSINT 历史论坛帖子定位：Silk Road 首次公开宣传帖 + 成员 ID + ROT13/Base64/SHA256 编码链](ctf-misc-osint-silk-road-first-forum-post-member-id.md) | verified | high | 2026-11-06 |
| [OSINT 跨平台用户名关联：Discord 句柄 → Steam 连接 → 曾用名历史取 flag](ctf-misc-osint-cross-platform-username-steam-former-name.md) | verified | high | 2026-11-06 |
| [output.png 位面提取内嵌 zip（条目 .b）→ Base85 解码 shellcode → 沙箱执行得 C2 IP（前置 dmp 按 raw 图像取域名）](ctf-misc-png-bitplane-zip-base85-shellcode-c2.md) | verified | low | 2026-11-09 |
| [PNG IDAT 块长度异常与未填满块后续块：识别人工插入的隐藏数据](ctf-misc-png-idat-chunk-anomaly-stego.md) | verified | high | 2026-11-06 |
| [PNG 尾部附加数据：LCG 流 XOR 解出 base62 密文再还原 flag](ctf-misc-png-trailing-data-lcg-xor-base62.md) | verified | high | 2026-11-06 |
| [PNG 非法 chunk 类型 Fl4G 藏 zlib 压缩流：提取解压得到隐藏 WAV](ctf-misc-png-invalid-chunk-type-zlib-wav-stego.md) | verified | high | 2026-11-06 |
| [PPM P6 文件头高度被篡改：按实际像素数重算高度还原隐藏行](ctf-misc-ppm-p6-header-height-tamper-hidden-rows.md) | verified | high | 2026-11-06 |
| [PPTX 幻灯片图片序列隐写：6/7 图片映射 0/1，每 9 张一个分隔符](ctf-misc-pptx-slide-image-binary-separator.md) | verified | high | 2026-11-06 |
| [PPTX/DOCX 多部件藏段：按 OOXML part 枚举 slide/slideLayout/media/comments/notesSlide/docProps/embeddings 并逐段解码拼 flag](ctf-misc-ooxml-multipart-slide-layout-media-comment-stego.md) | verified | high | 2026-11-09 |
| [RAR5 加密归档 + 注释泄露内层文件头：弱口令爆破后修复图片文件头取二维码](ctf-misc-rar5-header-repair-known-plaintext-weak-password.md) | verified | medium | 2026-11-07 |
| [RPG Maker VX Ace .rvdata2 取证：自解压 CAB 提取 + Ruby Marshal 字符串定位 flag](ctf-misc-rpgmaker-rvdata2-selfextract-cab.md) | verified | high | 2026-11-06 |
| [SIXEL DCS 图像流解码：终端图形隐写还原 flag](ctf-misc-sixel-dcs-image-decode.md) | verified | high | 2026-11-06 |
| [spammimic 垃圾邮件文本隐写：EML 正文提取与在线解码](ctf-misc-spammimic-spam-text-stego-eml.md) | verified | medium | 2026-11-06 |
| [TCP 半关闭语义指纹：gost 与 frp 代理识别与 PoW 交互](ctf-misc-proxy-half-close-gost-frp-fingerprint.md) | verified | high | 2026-11-06 |
| [TIFF 多图层隐写：普通查看器只显示顶层，用 PS/GIMP 分层查看隐藏 flag](ctf-misc-tiff-multilayer-hidden-image.md) | verified | high | 2026-11-06 |
| [Tupper 自指公式解码：大整数按 17 位列布局还原位图密码](ctf-misc-tupper-self-referential-formula-decode.md) | verified | high | 2026-11-06 |
| [Unicode 变体选择符隐写：U+FE00–U+FE0F 映射十六进制还原隐藏数据](ctf-misc-unicode-variation-selector-hex-stego.md) | verified | high | 2026-11-06 |
| [V8 d8 沙盒文件读取侧信道：import('./flag') 语法错误回显文件内容](ctf-misc-v8-d8-dynamic-import-syntax-error-file-read.md) | verified | high | 2026-11-06 |
| [WAV PCM 每 4 字节首字节写文本：3 字节小端长度前缀 + 步长 4 提取](ctf-misc-wav-every-fourth-byte-text-length-prefix.md) | verified | high | 2026-11-08 |
| [WAV 方波音频曼彻斯特隐写：读波形定起始时间与比特时长，多模式解码提取隐藏数据](ctf-misc-wav-manchester-encoding-waveform-extraction.md) | verified | high | 2026-11-08 |
| [WKCTF2024 不套是你的谎言：pyc 魔术头版本字典还原十六进制 + 伪加密 zip + DES/rockyou 爆破](ctf-misc-pyc-magic-dict-pseudo-zip-des-bruteforce.md) | verified | medium | 2026-11-08 |
| [xargs 超过 ARG_MAX 分批执行：第二批 argv[1] 被注入为 AES key，已知密钥解密 flag](ctf-misc-xargs-argmax-split-argv-key-injection.md) | verified | high | 2026-11-06 |
| [ZIP 本地文件头损坏与伪加密修复：补 50 4B 03 04 + 清零加密标志位](ctf-misc-zip-local-header-repair-pseudo-encryption.md) | verified | high | 2026-11-06 |
| [两个文本单字符差分取 ord 差值还原 flag](ctf-misc-text-diff-ord-delta-flag.md) | verified | high | 2026-11-06 |
| [交互题 checker 未校验查询下标上界：直接查询 A_n 每一位](ctf-misc-interactive-checker-missing-index-upper-bound.md) | verified | high | 2026-11-06 |
| [低频图像隐写：缩小或高斯模糊恢复隐藏图像](ctf-misc-low-frequency-image-downscale-blur-reveal.md) | verified | high | 2026-11-06 |
| [八卦五字组编码：笔画数减一拼 Unicode 十进制码点，卦象三爻转 ASCII](ctf-misc-bagua-five-stroke-minus-one-unicode-codepoint.md) | verified | high | 2026-11-06 |
| [固件 EEPROM 33 字节混淆串：单字节 XOR/ADD/SUB + ROL/ROR + NOT 组合爆破定位 flag](ctf-misc-firmware-eeprom-byte-transform-bruteforce-flag.md) | verified | high | 2026-11-07 |
| [图片尾部附加 ZIP 链：foremost 分离 + 伪加密修复 + PCZ 嵌套 ZIP 取 BMP flag](ctf-misc-image-appended-zip-pseudo-encryption-nested-pcz.md) | verified | high | 2026-11-06 |
| [多通道不可见 Unicode 隐写 + GF(2) 稀疏矩阵求解：Tag 字符藏 manifest、变体选择符藏 nonce、零宽字符藏 RHS](ctf-misc-multi-channel-invisible-unicode-gf2-sparse-matrix.md) | verified | high | 2026-11-06 |
| [字符频次反查编码：用出现次数作为索引恢复消息](ctf-misc-character-frequency-count-index-decode.md) | verified | high | 2026-11-06 |
| [嵌套 ZipCrypto BOX 链：密码=编号、Base32 短片段 CRC32 修复、9 字节重叠拼接 zlib](ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain.md) | verified | high | 2026-11-06 |
| [差分曼彻斯特解码 01 串还原 ZIP，按固定周期剔除插入字节修复，续爆破与 PixelJihad 提取 flag](ctf-misc-differential-manchester-decode-zip-repair-pixeljihad.md) | verified | high | 2026-11-08 |
| [按 mtime 排序文件名碎片重组 Base64：噪声过滤 + 增量解码恢复 flag](ctf-misc-mtime-ordered-filename-base64-fragments.md) | verified | high | 2026-11-06 |
| [损坏 Word 文档 ZIP 结构排查：按修改时间与缩略图定位背景图零宽隐写](ctf-misc-broken-docx-zip-mtime-thumbnail-stego.md) | verified | high | 2026-11-06 |
| [文件 mtime 末三位隐写：修改时间戳后三位映射 ASCII 字符](ctf-misc-mtime-last-three-digits-ascii.md) | verified | high | 2026-11-06 |
| [文本行首尾字符隐写：逐行取首尾非空白字符拼 flag](ctf-misc-first-last-char-line-stego.md) | verified | high | 2026-11-06 |
| [标点符号 2-bit 编码：四种标点映射 00/01/10/11 还原 ASCII](ctf-misc-punctuation-2bit-encoding.md) | verified | high | 2026-11-06 |
| [短路求值 + 昂贵表达式构造四态时间侧信道：50 次查询四叉搜索 100-bit 随机数](ctf-misc-short-circuit-expensive-expression-quaternary-timing.md) | verified | high | 2026-11-06 |
| [红警2 VXL 单位模型底部隐写：vxlse 在载具底面绘制 flag](ctf-misc-ra2-vxl-model-bottom-text-stego.md) | verified | high | 2026-11-06 |
| [红警2 地图层隐写：空地绘制 flag 与触发编辑器文本事件](ctf-misc-ra2-map-terrain-trigger-text-stego.md) | verified | high | 2026-11-06 |
| [红警2 广告牌 SHP 动画隐写：替换地图广告牌为自定义 GIF/AVI 内容](ctf-misc-ra2-billboard-shp-animation-stego.md) | verified | high | 2026-11-06 |
| [跨 IDL 时间修正穷举 + PCAP 密文重组 + SHA256-CTR KEYMAT 解密](ctf-misc-idl-time-correction-pcap-sha256-ctr-keymat.md) | verified | high | 2026-11-06 |
| [迷宫 BFS 路径的左右移动编码成 bit 流还原 flag](ctf-misc-maze-horizontal-move-bitstream.md) | verified | high | 2026-11-06 |
| [重复文本碎片逆序反转：3 字符片段从后往前拼接](ctf-misc-repeated-text-fragment-reverse.md) | verified | high | 2026-11-06 |
| [零宽字符隐写：U+200B/U+200C 二进制与五进制编码](ctf-misc-zero-width-unicode-binary-quinary-stego.md) | verified | high | 2026-11-06 |
| [黑盒交互状态机 + shadow 哈希 oracle：还原随机 wiring 并用 MITM/beam 搜索打开七层 seal](ctf-misc-prism-shadow-oracle-permutation-search.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
