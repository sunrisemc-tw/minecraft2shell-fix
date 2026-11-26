# minecraft2shell-fix

[![release](https://img.shields.io/github/v/release/sunrisemc-tw/minecraft2shell-fix?label=release)](https://github.com/sunrisemc-tw/minecraft2shell-fix/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![minecraft](https://img.shields.io/badge/minecraft-1.20.5%20%E2%80%93%2026.4-3ddc84)](https://github.com/sunrisemc-tw/minecraft2shell-fix#%E6%94%AF%E6%8F%B4%E5%93%AA%E4%BA%9B%E7%89%88%E6%9C%AC)
[![tests](https://img.shields.io/badge/tests-98%20passing-3ddc84)](https://github.com/sunrisemc-tw/minecraft2shell-fix/actions)

幫你的 Minecraft 擋掉「伺服器資源包字型」攻擊 —— 代價是小字稍微變柔（見下方對照圖）。

> ⚠️ 已在 macOS 上的真實遊戲客戶端（Fabric、Forge、NeoForge、原版＋`-javaagent`）確認掛鉤有生效，
> 但**沒有在 Windows 上實際跑過攻擊程式**。請當成「先擋一下」的過渡方案，不是官方修補。

### 免責聲明

此工具僅為臨時解方，不是 Mojang 官方修復。

此工具可能存在誤判和漏判的可能，且不保證可以攔截所有攻擊及異常警告是正確的。

此工具不負任何誤判和漏判的直接／間接經濟損失和相應責任，所有責任由使用者自行承擔。若您不同意，請**不要安裝，直接拒絕所有伺服器的資源包發送請求！**

---

## 中文

### 這是什麼問題（白話）

Minecraft 允許伺服器發「資源包」給玩家，裡面可以放字型檔。有人做出了攻擊：**在字型裡藏一段惡意程式，
玩家一畫到那個字，電腦就被執行任意程式**（公開示範只是開個小算盤，但同樣可以裝後門）。

問題出在遊戲畫字用的那套繪字引擎。**官方已經熱修了，但只修了新版**（詳見下方版本表）：26.2 以後換成自己重打包、內含 FreeType 2.15.0 的 natives；**1.20.5–1.21.10 仍然是舊的 2.13.2，沒有修**。

### 這個工具做什麼

**字型全部走「安全通道」：**所有字型載入時都關掉繪字引擎的 hinting（進階對齊）步驟。
攻擊之所以成立，是因為那一步會執行字型裡自帶的程式碼；關掉它，字型裡的程式就沒有機會跑。
這個做法**不需要先認出攻擊長什麼樣**，所以連還沒公開的變種也擋得住。

代價是畫質：少了 hinting，小字會稍微變糊。這是刻意的取捨 —— **用一點畫質換掉整類攻擊**。

**實際差多少，看圖最準（上排＝原版，下排＝本工具）：**

![hinting comparison](docs/images/hinting-comparison.png)

- 圖是**真的用 Minecraft 26.3 內建的同一個繪字引擎（FreeType 2.14.3）**畫出來的，不是示意圖；放大成像素格方便比較
- **HUD 那種 9px 小字差最多**（邊緣變柔、不再對齊像素格）；16px 還看得出來；32px 幾乎分不出來
- 量化：DejaVu Sans 32px 前 300 字元，**72% 點陣圖有變化、平均高度差 0.88 px、最差 2 px**
- 中文（CJK）字因為筆畫多，差異比英文更不明顯

如果你覺得小字糊到受不了，可以改用 `-Dm2sfix.policy=detect`：只有**可能執行到出問題那條指令（SHZ）**
的字型才關 hinting，其他字型保持原樣。這個判斷不依賴攻擊長什麼樣，但會順帶影響一部分正常字型
（在作者的 Mac 上約 11% 的字型會被降級）。

**只有偵測到高危才會跳警告視窗**（一般字型只是安靜降級，不會打擾你）：

```
檢測到伺服器的資源包疑似包含惡意內容（minecraft2shell），已經攔截。
這類字型可以在你的電腦上執行任意程式，這個伺服器送來的樣本沒有被執行。

[我了解，繼續遊玩]  [中斷連線]
```

按「中斷連線」會直接離開那個伺服器。不需要任何設定，也不影響遊戲效能。

想回到「只處理被判定為惡意字型」的舊行為（畫質優先）：
在 JVM 參數加 `-Dm2sfix.policy=detect`。

> 視窗裡**不會**顯示「它原本要執行什麼指令」。原因很實在：公開的那支攻擊程式把指令直接寫在
> 字型的程式碼裡組出來，144 個字型裡用任何編碼（ASCII／UTF-16／拆成 4 byte）都找不到
> `calc.exe`，沒有可靠辦法反推。與其顯示一個猜的，不如不顯示。

### 同類的圖片解碼洞（已納入防護）

同一條「伺服器發資源包 → 原生解碼器」路徑上還有一個洞（`stb_image`，PNG 走的解碼器），
**26.3 用的 `lwjgl-stb 3.4.3` 沒有熱修**：

- 資源包裡的 PNG 會交給 `stb_image`（透過 `lwjgl-stb`）解碼。Primitive One 公開的研究顯示：
  特製 PNG 可以造成原生堆積越界寫（實測必當）、以及「索引色盤未初始化」導致**洩漏原生記憶體
  （含 ASLR 相關指標）**，再透過可被資源包替換的 shader 以計時側通道回傳給伺服器。
  他們評為 7.1（High），若該伺服器資源包已預先信任則 8.2。
- 我在 26.3 用的 `lwjgl-stb 3.4.3` 上實測重現了越界寫：餵一個 23,171×23,171 的 16-bit 灰階 PNG
  給 `stbi_load_from_memory(..., 4)`，JVM 直接 SIGSEGV，`malloc(): corrupted top size`。
- **這個洞現在也有防護了**：本工具在 `STBImage.stbi_load_from_memory` 入口檢查圖片的標頭
  （尺寸、位元深度、色盤），算術一律用 64 位，超出上限就直接把緩衝區換成空的 → 解碼器正常失敗、
  遊戲顯示缺圖，而不是寫壞原生堆積。實測對照：同一張 23,171×23,171 的 16-bit PNG，
  掛上本工具 → `refused image … PROCESS_SURVIVED`；`-Dm2sfix.images=off` → `SIGSEGV`。
- 預設上限：16 Mpx、解碼後 64 MiB、單邊 16,777,216；可用 `-Dm2sfix.images.maxpixels=`
  與 `-Dm2sfix.images=off` 調整。
- **仍然不處理**：色盤未初始化的資訊洩漏（那需要看解碼後的像素資料）、以及任何標頭看起來正常
  卻仍能觸發的解碼器 bug。

### 支援哪些版本

我直接對 Mojang 的版本清單（Piston meta）與實際的原生函式庫驗證過：

我把每個版本的原生函式庫抓下來、直接呼叫 `FT_Library_Version` 量版本（不是看版本字串猜）：

| Minecraft | 實際內建的 FreeType | 有這個漏洞嗎 | 本工具 |
| --- | --- | --- | --- |
| 26.2 | **2.15.0**（`3.4.1-mojang-2.15.0.3`） | 已熱修 | 多餘（仍可當縱深防禦） |
| 26.3 / 26.4 快照 / 26.4-pre-1 | **2.15.0**（`3.4.3-mojang-2.15.0`） | 已熱修 | 多餘（仍可當縱深防禦） |
| 1.20.5 – 1.21.10 | **2.13.2**（`3.3.3`，無熱修） | **有** | ✅ 需要 |
| 1.20.4 及更早 | 沒有用 FreeType（走 stb_truetype） | 不是同一個洞 | ⛔ 不適用 |

- **官方是用「同名重新打包」修的**：版本號還寫 `3.4.3`，但 artifacts 是 `3.4.3-mojang-2.15.0`，裡面真的是 FreeType 2.15.0。所以「版本號看起來沒變」不代表沒修 —— 這也是我先前判斷錯的地方。
- 啟動器只要有重新抓 Mojang 的 library 清單，就會自動拿到修好的 natives；**會壞的是那些把 library 快取住、或整包 pin 在舊 natives 的整合包／離線安裝**。
- 1.20.5–1.21.10 完全沒有熱修，這是本工具目前最實際的用途。
- 1.20.4 以前的客戶端根本沒呼叫 FreeType，本工具掛上去也不會被觸發（不會壞，但也沒作用）。
- 舊版（1.20.5–1.21.x）跑的是 Java 21，本工具就是編 Java 21，可以直接用。

### 安裝（選一種就好）

**原版啟動器（官方啟動器）**

1. 到 [Releases](https://github.com/sunrisemc-tw/minecraft2shell-fix/releases) 下載 `m2sfix-agent-2.2.0.jar`，記住它放在哪
2. 啟動器 →「安裝檔」→ 你的版本 →「編輯」→「更多選項」
3. 在「JVM 參數」那欄最後面加上（路徑換成你放的位置）：
   ```
   -javaagent:/你的路徑/m2sfix-agent-2.2.0.jar
   ```
4. 儲存，啟動遊戲

**Fabric**

下載 `m2sfix-mod-2.2.0.jar`，丟進 `.minecraft/mods/` 就好（不需要 Fabric API）。

**Forge / NeoForge**

同一顆 `m2sfix-mod-2.2.0.jar` 丟進 `mods/`。已實測 Forge 1.20.6、1.21.10 與 NeoForge 1.20.5、1.20.6、
1.21.10、26.3。如果掛鉤沒套上，遊戲會**直接停止啟動並告訴你改用 `-javaagent`**，不會默默失效。

> 注意：在 Forge / NeoForge 上，模組只保護 Minecraft 自己畫字的地方。如果你有裝**其他自己呼叫
> FreeType 的模組**，改用 `-javaagent`，它會攔住所有呼叫。

### 怎麼知道有沒有生效

啟動後日誌裡會出現這兩行，代表掛鉤真的有在工作：

```
[m2sfix] guard active: FT_New_Memory_Face intercepted (policy=safe)
[m2sfix] guard active: FT_Load_Glyph intercepted (policy=safe)
```

遇到惡意字型時會多一行（並跳警告視窗）：

```
[m2sfix] flagged font 11500c6f… (SUSPICIOUS): IDEF redefines point-zone opcode 0x36 in fpgm
```

警告視窗在 Forge、NeoForge 26.x 與 Fabric＋`-javaagent` 上實測會出現；在原版 1.21.x 和一般
Fabric 1.21.x 上會改成寫進日誌（遊戲內部名稱被混淆，找不到視窗類別）。不論哪種，字型都已經被處理。

### 需要注意的地方

- 預設模式（safe）不需要認得攻擊；警告視窗則只認得「已知的那一類手法」，新變種可能被安靜擋下但不跳警告
- 真正的解法是等 Minecraft 更新繪字引擎（FreeType 2.15.0 以上），這個工具只是過渡
- 實機測試都在 macOS（Apple Silicon）上；Windows / Linux 沒有實機跑過
- 警告視窗的按鈕只在單元測試驗證過，沒有在遊戲裡實際點過

### 授權

MIT。自由使用、修改、再散布。

### 想更深入了解

- 掛點位置、偵測原理、設定選項、測試數據 → **[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md)**
- 攻擊是怎麼運作的（逐步拆解公開 PoC）→ **[docs/EXPLOIT-ANALYSIS.md](docs/EXPLOIT-ANALYSIS.md)**
- 版本紀錄 → **[CHANGELOG.md](CHANGELOG.md)**
- 研究這個專案碰到什麼問題 → **[SECURITY.md](SECURITY.md)**

---

## English

A client-side mitigation for the Minecraft "server resource pack font" attack. The price is slightly
softer small text (see the comparison below).

> ⚠️ The hooks were confirmed working in real game clients on macOS (Fabric, Forge, NeoForge, and
> vanilla with `-javaagent`), but **the exploit itself was never run against it on Windows**. Treat it
> as a stopgap, not a vendor fix.

### Disclaimer

This tool is a temporary workaround, not an official Mojang fix.

It may produce false positives and false negatives, and it cannot guarantee that it blocks every
attack or that any warning it shows is correct.

The author accepts no liability for any direct or indirect financial loss or other consequences of
false positives or false negatives; all responsibility rests with the user. If you do not agree,
**do not install it — just decline every server resource-pack request instead!**

### The problem, in plain words

A Minecraft server can send players a resource pack that contains a font. Someone figured out how to
hide a malicious program inside such a font: **the moment the game draws a character with it, the
player's computer can be made to run arbitrary code.** The flaw is in the font engine the game uses,
and **Minecraft has not shipped a fix yet.**

### What this does

**Every font goes through a safe channel:** glyph loading always skips the "hinting" step of the font
engine. The attack only works because that step executes bytecode embedded in the font; skip it and
the font's own program never runs. This needs no idea of what the attack looks like, so variants that
are not public yet are covered too.

The cost is rendering quality: without hinting, small text looks slightly softer. That is the
deliberate trade — **a little sharpness for a whole class of bugs**.

**See exactly how much (top row = vanilla, bottom row = this tool):**

![hinting comparison](docs/images/hinting-comparison.png)

- Rendered with the **same font engine Minecraft 26.3 ships (FreeType 2.14.3)**, then zoomed with
  nearest-neighbour so individual pixels are visible — not a mock-up
- **HUD-sized 9 px text changes the most** (softer edges, no longer pixel-aligned); 16 px is still
  noticeable; at 32 px you can barely tell
- Measured on DejaVu Sans at 32 px, first 300 glyphs: **72% of bitmaps change, mean height
  difference 0.88 px, worst case 2 px**
- CJK text shows the difference even less, because dense strokes hide it

If the softness bothers you, switch to `-Dm2sfix.policy=detect`: only fonts whose bytecode **could
execute the faulty instruction (`SHZ`)** lose hinting; everything else stays vanilla. This does not
depend on recognising the attack, but it also catches some ordinary fonts (about 11% of the faces
installed on the author's Mac).

**A warning dialog appears only for high-confidence hits** (ordinary fonts are just quietly degraded):

```
This server's resource pack looks malicious (minecraft2shell). It was blocked and did not run;
fonts like this can execute arbitrary code on the client.

[Continue]  [Disconnect]
```

"Disconnect" leaves that server immediately. No configuration, no measurable performance cost.

> The dialog deliberately does **not** show "the command it would have run". The published exploit
> builds its command inside the font's own bytecode: `calc.exe` appears in none of the 144 shipped
> fonts in any encoding (ASCII, UTF-16, 4-byte split), so there is no reliable way to recover it.
> Showing a guess would be worse than showing nothing.

### The sibling image-decoder bug (now also guarded)

The same shape — server-supplied pack reaching a native decoder — has a sibling bug in `stb_image`
(the PNG decoder), and **26.3's `lwjgl-stb 3.4.3` has no hotfix**:

- PNGs in a pack are decoded by `stb_image` (through `lwjgl-stb`). Primitive One's published research
  shows a crafted PNG causing a native heap out-of-bounds write (reliable crash), plus an
  uninitialised-palette read that **discloses native memory (ASLR-relevant pointers)** and a
  timing side channel through a pack-supplied shader to send it back. They rate it 7.1 High
  (8.2 if the server's pack was already trusted).
- I reproduced the write on the `lwjgl-stb 3.4.3` that 26.3 ships: handing a 23,171×23,171 16-bit
  greyscale PNG to `stbi_load_from_memory(..., 4)` kills the JVM with SIGSEGV,
  `malloc(): corrupted top size`.
- **This is guarded now too**: the guard inspects the image header at the
  `STBImage.stbi_load_from_memory` entry point (dimensions, bit depth, palette), does all arithmetic in
  64-bit, and swaps in an empty buffer when the geometry cannot fit — the decoder then fails normally
  and the game shows a missing texture instead of corrupting the native heap. Measured side by side
  with the same 23,171×23,171 16-bit PNG: with the guard → `refused image … PROCESS_SURVIVED`;
  with `-Dm2sfix.images=off` → `SIGSEGV`.
- Defaults: 16 Mpx, 64 MiB decoded, 16,777,216 per axis; adjust with
  `-Dm2sfix.images.maxpixels=`, disable with `-Dm2sfix.images=off`.
- **Still not covered**: the uninitialised-palette information leak (that needs decoded pixels), and
  any decoder bug reachable with a perfectly reasonable header.

### Supported versions

Checked against Mojang's own version manifest (Piston meta) and the actual native libraries:

| Minecraft | bundled FreeType | vulnerable | this tool |
| --- | --- | --- | --- |
| 26.3 / 26.4 snapshots | 2.14.3 (LWJGL 3.4.3) | yes | ✅ |
| 26.1 – 26.2 | 2.14.1 (LWJGL 3.4.1) | yes | ✅ |
| 1.20.5 – 1.21.10 | 2.13.2 (LWJGL 3.3.3) | yes | ✅ |
| 1.20.4 and older | no FreeType (stb_truetype) | a different bug | ⛔ not applicable |

- Mojang **has** patched it, by republishing the same version number with a suffix: the artifacts are
  `lwjgl-freetype-3.4.3-mojang-2.15.0` (26.3, 26.4 snapshots, 26.4-pre-1) and
  `3.4.1-mojang-2.15.0.3` (26.2). I downloaded those natives and printed `FT_Library_Version`: both
  report **2.15.0**, the fixed release. The version *number* looking unchanged does not mean it is
  unfixed — I got that wrong once, which is why the table above is measured rather than grepped.
- 1.20.5 – 1.21.10 ship plain `lwjgl-stb`/`lwjgl-freetype 3.3.3` = FreeType **2.13.2**, with no
  hotfix, so those are the versions this tool is actually for.
- Before 1.20.5 the client never calls FreeType, so the hooks are never reached (harmless, but no
  effect either).
- 1.20.5 – 1.21.x run Java 21, which is what this project targets, so they work as-is.

### Install (pick one)

**Vanilla launcher**

1. Download `m2sfix-agent-2.2.0.jar` from [Releases](https://github.com/sunrisemc-tw/minecraft2shell-fix/releases)
2. Launcher → Installations → your instance → Edit → More options
3. Append to "JVM arguments" (use your own path):
   ```
   -javaagent:/full/path/to/m2sfix-agent-2.2.0.jar
   ```
4. Save and launch

**Fabric**

Drop `m2sfix-mod-2.2.0.jar` into `.minecraft/mods/` (no Fabric API needed).

**Forge / NeoForge**

The same `m2sfix-mod-2.2.0.jar` goes into `mods/`. Tested on Forge 1.20.6 and 1.21.10 and NeoForge
1.20.5, 1.20.6, 1.21.10 and 26.3. If the hooks cannot apply, the game **stops at startup and tells
you to use `-javaagent`** instead of silently running unprotected.

> On Forge / NeoForge the mod protects Minecraft's own font rendering. If you also run **other mods
> that call FreeType themselves**, use the `-javaagent` route, which intercepts every call.

### Did it work?

After startup the log shows that the hooks are live:

```
[m2sfix] guard active: FT_New_Memory_Face intercepted (policy=safe)
[m2sfix] guard active: FT_Load_Glyph intercepted (policy=safe)
```

A known-malicious font adds a line (and the warning dialog):

```
[m2sfix] flagged font 11500c6f… (SUSPICIOUS): IDEF redefines point-zone opcode 0x36 in fpgm
```

The dialog was seen opening on Forge, NeoForge 26.x and Fabric with `-javaagent`. On obfuscated
vanilla 1.21.x and plain Fabric 1.21.x the warning goes to the log instead; the font is handled
either way.

### Caveats

- The default `safe` mode needs no signature; the warning dialog does, so a new variant may be
  neutralised silently without a warning
- The real fix is a Minecraft update that ships FreeType ≥ 2.15.0 — this is a stopgap
- Real-client testing was done on macOS (Apple Silicon); Windows and Linux were not run live
- The dialog buttons are verified by unit tests only, not clicked in a running game

### License

MIT.

### Going deeper

- Hook points, detection logic, configuration, test data → **[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md)**
- How the attack works, step by step → **[docs/EXPLOIT-ANALYSIS.md](docs/EXPLOIT-ANALYSIS.md)**
- Version history → **[CHANGELOG.md](CHANGELOG.md)**
- Reporting a bypass → **[SECURITY.md](SECURITY.md)**
