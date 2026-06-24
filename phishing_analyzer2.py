# -*- coding: utf-8 -*-
"""
=====================================================================
 釣魚特徵分析器（Streamlit）— 純防禦端教學工具
 逢甲大學資工系學士後專班 — 資訊安全期末報告
 作者：彭禹翔
---------------------------------------------------------------------
 功能：
   1) URL 釣魚特徵分析（規則式、可解釋）
   2) 可疑文字 / 郵件內容的社交工程話術偵測（規則式）
   3) 「AI 協作」示範：可選擇呼叫 Claude API 做語義分析
      —— API 金鑰從環境變數讀取，絕不寫死在程式碼中。
---------------------------------------------------------------------
 執行方式：
   pip install streamlit anthropic
   streamlit run phishing_analyzer2.py
 （若要啟用 AI 功能：先 export ANTHROPIC_API_KEY="你的金鑰"）
=====================================================================
"""

import os
import re
from urllib.parse import urlparse

import streamlit as st

# ---------------------------------------------------------------------
# 常數：特徵字典（與網頁版 Demo B 一致，方便交叉對照）
# ---------------------------------------------------------------------
BRANDS = ["paypal", "google", "apple", "appie", "app1e", "microsoft",
          "facebook", "amazon", "line", "bank", "chase", "netflix",
          "instagram", "icloud", "office365"]

URL_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update",
                "confirm", "password", "webscr", "banking", "wallet",
                "suspend", "unlock"]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd",
              "ow.ly", "reurl.cc", "pse.is"]

RISKY_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf",
              ".gq", ".work", ".click", ".zip", ".mov"]

# 社交工程「話術」關鍵詞（中英都涵蓋）
SE_TACTICS = {
    "急迫 / 恐嚇": ["立即", "馬上", "24小時內", "盡快", "逾期", "凍結", "停用",
                 "帳號異常", "urgent", "immediately", "suspend", "expire", "within 24"],
    "權威 / 冒名": ["銀行", "系統管理員", "客服", "官方", "資訊部", "政府",
                 "admin", "support team", "it department", "official"],
    "誘因 / 貪婪": ["中獎", "退款", "獎金", "免費", "優惠", "紅利",
                 "refund", "prize", "reward", "bonus", "free gift"],
    "要求機敏資訊": ["密碼", "驗證碼", "otp", "信用卡", "身分證", "帳號",
                 "verify your", "confirm your password", "click here to login"],
}


# ---------------------------------------------------------------------
# 規則引擎 1：URL 分析
# ---------------------------------------------------------------------
def analyze_url(raw: str):
    """回傳 (score, findings)；findings 為 list[dict]。"""
    raw = raw.strip()
    s = raw if re.match(r"^https?://", raw, re.I) else "http://" + raw
    try:
        u = urlparse(s)
    except ValueError:
        return None, []

    host = (u.hostname or "").lower()
    full = raw.lower()
    parts = host.split(".") if host else []
    tld = "." + parts[-1] if parts else ""
    registrable = ".".join(parts[-2:]) if len(parts) >= 2 else host

    findings = []

    def add(hit, weight, title, desc):
        findings.append({"hit": hit, "weight": weight, "title": title, "desc": desc})

    # 1 HTTPS
    add(u.scheme != "https", 15, "缺少 HTTPS 加密",
        "登入頁卻用 http://，連線未加密。" if u.scheme != "https" else "使用 https://。")

    # 2 IP 位址
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    add(is_ip, 25, "直接使用 IP 位址",
        "正規服務極少用裸 IP 當登入網址。" if is_ip else "使用網域名稱。")

    # 3 @ 符號
    has_at = "@" in raw
    add(has_at, 20, '網址含有 "@" 符號',
        "瀏覽器只認 @ 之後的主機，常被用來藏真實惡意網域。" if has_at else "未使用 @ 混淆。")

    # 4 子網域過多
    sub_count = max(0, len(parts) - 2)
    add(sub_count >= 3, 15, "子網域層數過多",
        f"偵測到 {sub_count} 層子網域。" if sub_count >= 3 else f"子網域層數正常（{sub_count}）。")

    # 5 品牌名出現在非主網域 ★ 最強特徵
    brand_hit, brand = False, ""
    for b in BRANDS:
        if b in full and b not in registrable:
            brand_hit, brand = True, b
            break
    add(brand_hit, 30, "品牌名出現在非主網域位置",
        f"出現「{brand}」卻不在主網域（真正網域為 {registrable}）——典型冒名。"
        if brand_hit else "未發現品牌被塞在子網域/路徑。")

    # 6 高風險關鍵字
    kw = [k for k in URL_KEYWORDS if k in full]
    add(len(kw) >= 2, 10, "含多個高風險關鍵字",
        f"偵測到：{', '.join(kw)}。" if kw else "未發現明顯關鍵字。")

    # 7 過長
    add(len(raw) > 75, 8, "網址異常冗長",
        f"長度 {len(raw)} 字元。" if len(raw) > 75 else f"長度正常（{len(raw)}）。")

    # 8 高風險 TLD
    risky = tld in RISKY_TLDS
    add(risky, 15, "使用高風險頂級網域",
        f"{tld} 常被釣魚濫用。" if risky else f"{tld} 風險較低。")

    # 9 短網址
    is_short = any(host.endswith(x) for x in SHORTENERS)
    add(is_short, 12, "使用短網址服務",
        "短網址會隱藏真實目的地。" if is_short else "非短網址。")

    # 10 同形 / 拼字仿冒
    leet = host.replace("0", "o").replace("1", "l").replace("3", "e")
    typo = any(b in leet for b in BRANDS) and bool(re.search(r"\d", host))
    puny = "xn--" in host
    add(puny or typo, 18, "疑似同形/拼字仿冒",
        "偵測到 Punycode 或數字替字母（如 app1e、g00gle）。" if (puny or typo)
        else "未發現明顯仿冒。")

    score = min(100, sum(f["weight"] for f in findings if f["hit"]))
    return score, findings


# ---------------------------------------------------------------------
# 規則引擎 2：可疑文字 / 郵件話術分析
# ---------------------------------------------------------------------
def analyze_text(text: str):
    text_low = text.lower()
    hits = {}
    for tactic, words in SE_TACTICS.items():
        found = [w for w in words if w.lower() in text_low]
        if found:
            hits[tactic] = found
    # 額外：可疑連結
    urls = re.findall(r"https?://[^\s)>\]]+", text)
    return hits, urls


# ---------------------------------------------------------------------
# AI 協作（可選）：呼叫 Claude 做語義分析
#   —— 金鑰只從環境變數讀，不寫死。沒設定金鑰時自動停用。
# ---------------------------------------------------------------------
def ai_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def call_claude(prompt: str) -> str:
    try:
        import anthropic
    except ImportError:
        return "（尚未安裝 anthropic 套件：pip install anthropic）"
    try:
        client = anthropic.Anthropic()  # 自動讀取 ANTHROPIC_API_KEY
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    except Exception as e:  # noqa: BLE001
        return f"（呼叫 AI 失敗：{e}）"


def build_ai_prompt(target: str, kind: str, summary: str) -> str:
    return (
        "你是一位資安分析師，請用『計算機概論程度學生』也能懂的方式分析。\n\n"
        f"【分析對象（{kind}）】\n{target}\n\n"
        f"【規則式工具的初步結果】\n{summary}\n\n"
        "請完成：\n"
        "1. 綜合判斷釣魚 / 社交工程可能性（低/中/高）與理由。\n"
        "2. 補充規則看不出的語意與心理操弄線索。\n"
        "3. 給使用者 3 個可立即執行的自保建議。\n"
        "4. 全程教育導向、中立，不得提供任何可用於實際攻擊的內容。"
    )


# ---------------------------------------------------------------------
# 共用：渲染 URL 的判斷依據
# ---------------------------------------------------------------------
def render_url_findings(score: int, findings: list):
    level = ("🔴 高風險" if score >= 50 else
             "🟡 中度可疑" if score >= 20 else "🟢 風險較低")
    st.metric("釣魚風險分數", f"{score} / 100", level)
    st.progress(score / 100)

    st.subheader("判斷依據")
    for f in sorted(findings, key=lambda x: (not x["hit"], -x["weight"])):
        icon = "🚩" if f["hit"] else "✅"
        w = f"  `+{f['weight']}`" if f["hit"] else ""
        st.markdown(f"{icon} **{f['title']}**{w}  \n{f['desc']}")


# =====================================================================
# Streamlit 介面
# =====================================================================
st.set_page_config(page_title="釣魚特徵分析器", page_icon="🛡️", layout="centered")

st.title("🛡️ 釣魚特徵分析器")
st.caption("純防禦端教學工具 · 規則式分析在本機完成 · AI 分析為可選")

st.warning(
    "⚠️ 教育與防禦用途。本工具用於『辨識與防禦』釣魚，"
    "不可用於製作或散布釣魚內容。製作釣魚網站竊取資料將觸犯《刑法》第339條與《個資法》。",
    icon="⚠️",
)

tab1, tab2 = st.tabs(["🔗 URL 分析", "✉️ 可疑文字 / 郵件分析"])

# ---------- Tab 1：URL ----------
with tab1:
    url = st.text_input("輸入要檢查的網址",
                        placeholder="http://example.com/login", key="url_input")

    # 「分析」只負責計算並把結果寫進 session_state，重新分析時清掉舊的 AI 回應
    if st.button("分析網址", type="primary", key="btn_url"):
        if not url.strip():
            st.session_state.pop("url_result", None)
            st.session_state.pop("url_ai", None)
            st.info("請先輸入網址。")
        else:
            score, findings = analyze_url(url)
            st.session_state.url_result = {"url": url, "score": score, "findings": findings}
            st.session_state.pop("url_ai", None)

    # 結果區塊改在 if 之外渲染：session_state 會跨重跑保留，AI 按鈕才點得動
    if "url_result" in st.session_state:
        r = st.session_state.url_result
        score, findings, analyzed_url = r["score"], r["findings"], r["url"]

        if score is None:
            st.error("無法解析這個網址。")
        else:
            render_url_findings(score, findings)

            hit_summary = "\n".join(
                f"- {f['title']}：{f['desc']}" for f in findings if f["hit"]
            ) or "- （未命中明顯特徵）"
            prompt = build_ai_prompt(analyzed_url, "URL", f"風險分數 {score}/100\n{hit_summary}")

            st.divider()
            st.subheader("🤖 AI 語義分析（可選）")
            st.code(prompt, language="text")

            if ai_available():
                if st.button("呼叫 Claude 進行語義分析", key="btn_url_ai"):
                    with st.spinner("分析中…"):
                        st.session_state.url_ai = call_claude(prompt)
                if "url_ai" in st.session_state:
                    st.markdown(st.session_state.url_ai)
            else:
                st.info("未偵測到 ANTHROPIC_API_KEY，AI 呼叫已停用。"
                        "你可以直接複製上方 Prompt，貼到任一 AI 助手。")

# ---------- Tab 2：文字 ----------
with tab2:
    text = st.text_area("貼上可疑郵件 / 訊息內容", height=200,
                        placeholder="例如：您的帳號異常，請於24小時內點擊連結驗證密碼…",
                        key="text_input")

    if st.button("分析文字", type="primary", key="btn_text"):
        if not text.strip():
            st.session_state.pop("text_result", None)
            st.session_state.pop("text_ai", None)
            st.info("請先貼上內容。")
        else:
            hits, urls = analyze_text(text)
            st.session_state.text_result = {"text": text, "hits": hits, "urls": urls}
            st.session_state.pop("text_ai", None)

    if "text_result" in st.session_state:
        r = st.session_state.text_result
        analyzed_text, hits, urls = r["text"], r["hits"], r["urls"]

        if hits:
            st.subheader("偵測到的社交工程話術")
            for tactic, words in hits.items():
                st.markdown(f"🚩 **{tactic}** — 命中關鍵詞：`{', '.join(words)}`")
        else:
            st.success("未命中明顯的社交工程話術，但仍請保持警覺。")

        if urls:
            st.subheader("文中夾帶的連結")
            for link in urls:
                s2, _ = analyze_url(link)
                score_disp = s2 if s2 is not None else "—"
                tag = ("🔴" if s2 and s2 >= 50 else "🟡" if s2 and s2 >= 20 else "🟢")
                st.markdown(f"{tag} `{link}` — 風險分數 {score_disp}/100")

        summary = "命中話術：" + (", ".join(hits.keys()) if hits else "無")
        prompt = build_ai_prompt(analyzed_text, "郵件/訊息文字", summary)

        st.divider()
        st.subheader("🤖 AI 語義分析（可選）")
        st.code(prompt, language="text")

        if ai_available():
            if st.button("呼叫 Claude 分析這段文字", key="btn_text_ai"):
                with st.spinner("分析中…"):
                    st.session_state.text_ai = call_claude(prompt)
            if "text_ai" in st.session_state:
                st.markdown(st.session_state.text_ai)
        else:
            st.info("未偵測到 ANTHROPIC_API_KEY，AI 呼叫已停用。"
                    "可直接複製上方 Prompt 使用。")

st.divider()
st.caption("規則式偵測為輔助參考；最終仍應以官方來源、多重驗證與密碼管理員為準。")
