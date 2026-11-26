# FontGuard — Modrinth listing material

Everything below is ready to paste into the Modrinth "Create a project" form and its version
uploader. Nothing here has been submitted yet.

- **Name:** `FontGuard`
- **Slug (URL):** `fontguard`
- **Summary** (the one-line field, ≤256 chars):

```
擋下 Minecraft 資源包字型攻擊（minecraft2shell）：所有字型都不執行字型自帶的程式碼，正常字型只是少一點 hinting。Blocks the resource-pack font RCE without needing a signature.
```

- **Project type:** Mod
- **Environment:** Client only (server `unsupported`, client `required`)
- **Loaders:** Fabric, Forge, NeoForge
- **Game versions:** 1.20.5 — 26.4 (snapshots included: 26.4-snapshot-1 … 26.4-snapshot-10)
- **License:** MIT
- **Links:** source `https://github.com/sunrisemc-tw/minecraft2shell-fix`,
  issues `…/issues`, wiki none
- **Categories:** `utility`, `management` (Modrinth has no "security" category; pick these and let the
  description carry the security framing)
- **Icon:** `assets/icon-512.png`
- **Gallery:** `assets/banner-1280x720.png` (first), then
  `https://github.com/sunrisemc-tw/minecraft2shell-fix/blob/main/docs/images/hinting-comparison.png`
  — upload that PNG directly, description: "同一段文字，上排原版／下排本工具，用 Minecraft 26.3 內建的
  FreeType 2.14.3 實際渲染（像素放大）"

---

## Description (paste as-is; Modrinth renders Markdown)

```markdown
**這個模組不做「偵測攻擊」，它直接讓攻擊沒有機會發生。**

Minecraft 允許伺服器發資源包給玩家，裡面可以放 `.ttf` 字型。有人證明：只要在字型裡藏對的
bytecode，玩家畫到那個字的瞬間就可能被執行任意程式（公開 PoC：`bikini/minecraft2shell`，
Windows + Minecraft 26.3）。問題出在遊戲內建的繪字引擎 FreeType 2.14.3，**Mojang 到目前
（26.3 / 26.4 快照）都還沒換版本**。

FontGuard 的做法是：**所有字型載入時都不執行 hinting**。攻擊的那一步就是「執行字型自帶的
程式碼」，關掉它，字型裡的程式就沒有機會跑。因為完全不需要認出攻擊長相，**還沒公開的變種
也一樣擋得住**。

### 代價（請先看過再裝）

少了 hinting，字會稍微變柔，**小字最明顯**：

- 9px（介面文字大小）：邊緣變柔、不再對齊像素格
- 16px：看得出來
- 32px：幾乎分不出來
- 中文因為筆畫密，比英文更不明顯

量化：DejaVu Sans 32px 前 300 字元，72% 點陣圖有變化、平均高度差 0.88px、最差 2px。

![hinting comparison](https://raw.githubusercontent.com/sunrisemc-tw/minecraft2shell-fix/main/docs/images/hinting-comparison.png)

如果你覺得小字糊到受不了，可以在 JVM 參數加 `-Dm2sfix.policy=detect`：只有可能執行到
出問題那條指令（SHZ）的字型才關 hinting，其他保持原樣（約 11% 的一般字型也會被降級）。

### 什麼時候會跳警告

只有**高信心**命中（`IDEF` 改寫位移類指令、或在字形程式裡定義指令）才會跳視窗：

> 檢測到伺服器的資源包疑似包含惡意內容（minecraft2shell），已經攔截。
> [我了解，繼續遊玩] [中斷連線]

一般字型只是安靜降級，不會打擾你。同一場遊戲只跳一次。

### 支援版本

| Minecraft | 內建 FreeType | 本模組 |
| --- | --- | --- |
| 26.3 / 26.4 快照 | 2.14.3 | ✅ |
| 26.1 – 26.2 | 2.14.1 | ✅ |
| 1.20.5 – 1.21.10 | 2.13.2 | ✅ |
| 1.20.4 及更早 | 沒用 FreeType | ⛔ 不適用 |

（以上是用 Mojang 版本清單＋實際原生函式庫驗證的版本號，不是猜的。）

### 免責聲明

此工具僅為臨時解方，不是 Mojang 官方修復。此工具可能存在誤判和漏判的可能，且不保證可以
攔截所有攻擊及異常警告是正確的。此工具不負任何誤判和漏判的直接／間接經濟損失和相應責任，
所有責任由使用者自行承擔。若您不同意，請**不要安裝，直接拒絕所有伺服器的資源包發送請求！**

---

## English

**This mod does not detect the attack — it removes the step the attack needs.**

A Minecraft server can send a resource pack containing a `.ttf` font. Someone proved that a crafted
font can turn glyph hinting into arbitrary code execution (public PoC: `bikini/minecraft2shell`,
Windows + Minecraft 26.3). The flaw is in the bundled FreeType 2.14.3, and Mojang has not shipped a
newer one yet (not in 26.3, not in the 26.4 snapshots).

FontGuard loads **every** font with hinting disabled. That step is exactly what runs the font's own
bytecode, so disabling it means the font's program never runs — no signature has to match, which
means unpublished variants are covered too.

**The cost:** text loses hinting and looks slightly softer, most visibly at small sizes (9 px HUD
text). Measured on DejaVu Sans at 32 px: 72% of glyph bitmaps change, mean height difference 0.88 px.
Use `-Dm2sfix.policy=detect` if you prefer sharpness and accept signature-only coverage.

**Warning dialog** appears only for high-confidence hits; ordinary fonts are just quietly degraded.

**Disclaimer.** This is a temporary workaround, not an official Mojang fix. It may produce false
positives and false negatives and makes no guarantee. The author accepts no liability; all
responsibility rests with the user. If you do not agree, do not install it.
```

---

## Version uploads

Modrinth treats each loader separately, so publish **two versions from the same jar**:

### Version 1 — Fabric

- **Name:** `2.2.0 (Fabric)`
- **Version number:** `2.2.0`
- **Release channel:** Release
- **Loaders:** Fabric
- **Game versions:** 1.20.5, 1.20.6, 1.21, 1.21.1, 1.21.2, 1.21.3, 1.21.4, 1.21.5, 1.21.6, 1.21.7,
  1.21.8, 1.21.9, 1.21.10, 26.1, 26.2, 26.3, 26.4-snapshot-1 … 26.4-snapshot-10
- **File:** `m2sfix-mod-2.2.0.jar`
- **Dependencies:** none

### Version 2 — Forge / NeoForge

- **Name:** `2.2.0 (Forge / NeoForge)`
- **Version number:** `2.2.0`
- **Release channel:** Release
- **Loaders:** Forge, NeoForge
- **Game versions:** same list as above
- **File:** the same `m2sfix-mod-2.2.0.jar` (it carries `mods.toml`, `neoforge.mods.toml` and the
  `MixinConfigs` manifest entry alongside `fabric.mod.json`)
- **Dependencies:** none

> Tested in real clients on macOS: Forge 1.20.6 / 1.21.10, NeoForge 1.20.5 / 1.20.6 / 1.21.10 / 26.3
> (see `docs/LOADERS.md`). On Forge/NeoForge the mod covers Minecraft's own FreeType calls; users of
> other mods that call FreeType should use the javaagent from the GitHub release.

### Changelog field (both versions)

```
2.1.0 — 支援 1.20.5 以上（實測各版本內建 FreeType：26.3/26.4 快照 = 2.14.3、26.1–26.2 = 2.14.1、
1.20.5–1.21.10 = 2.13.2，全部早於修好的 2.15.0），新增畫質對比圖。

2.0.0 — 預設改走安全通道：所有字型都不執行 hinting，警告只在高信心命中時出現。

1.x — 特徵偵測版本（IDEF 改寫位移指令），PoC 字型 144/144 標記。
```

---

## Upload checklist (manual, ~15 minutes)

1. **建立專案** → Modrinth → *Create a project* → type **Mod**
2. 貼上 name / slug / summary / description；Environment 選 **Client: required, Server: unsupported**
3. 上傳 **icon** `assets/icon-512.png`
4. Gallery：先傳 `assets/banner-1280x720.png`，再傳畫質對比圖（描述照上面）
5. Categories：`utility`、`management`
6. Links：source / issues 指向 GitHub
7. **Save** → 進專案頁 → *Versions* → *Create version*，照上面「Version 1 / Version 2」各建一版，
   上傳同一個 jar
8. 確認版本頁的 game version 標籤有 1.20.5 與 26.3

### 或用 API（需要你自己建 token）

在 <https://modrinth.com/settings/pats> 建一個有 `CREATE_VERSION` + `PROJECT_CREATE` 權限的
Personal Access Token，然後：

```bash
export MODRINTH_TOKEN=...        # 不要貼在聊天室
bash modrinth/publish.sh          # 腳本已備好，會先做 dry-run 檢查檔案齊不齊
```

`publish.sh` 不會自己決定版本號或描述：它讀同目錄的 `project.json`、`version-fabric.json`、
`version-forge.json`，缺少必要欄位就直接中止。

---

## 上架前還要決定的事

- **專案名稱衝突**：Modrinth 上已經有一個叫 `Minecraft2Shell` 的 Fabric mod（可以在客戶端跑 OS
  指令）。用 `FontGuard` 當主名稱、描述裡提一次 minecraft2shell-fix，可以避免被搜尋混淆。
- **GitHub repo 要不要一起改名**：改了 release 連結會變。目前的做法是**不改**，Modrinth 用
  `fontguard` slug，兩邊都能搜到。
