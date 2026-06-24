# phish_analyzer.py
# 執行方式：pip install streamlit pandas
# streamlit run phish_analyzer.py

import streamlit as st
import pandas as pd
from datetime import datetime
import re

st.set_page_config(page_title="PhishAnalyzer - 釣魚 URL 教育分析器", page_icon="🛡️", layout="wide")

st.title("🛡️ PhishAnalyzer")
st.caption("釣魚網站 URL 特徵分析工具（教育用途）｜計算機概論期末報告 Demo")

tab1, tab2 = st.tabs(["🔍 URL 特徵分析（規則為主）", "🤖 AI 協作 Prompt 展示區"])

with tab1:
    st.subheader("輸入可疑 URL 進行即時分析")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        url_input = st.text_input("請輸入或貼上可疑網址", 
                                  value="https://taiwan-bank-login-secure-verify.com/update-account?session=abc123",
                                  placeholder="https://...")
    
    with col2:
        analyze_btn = st.button("開始分析", type="primary", use_container_width=True)
    
    # 範例按鈕
    st.write("快速測試範例：")
    ex_col1, ex_col2, ex_col3 = st.columns(3)
    with ex_col1:
        if st.button("✅ 正常範例", use_container_width=True):
            st.session_state.example_url = "https://www.taiwanbank.com.tw/ibank/"
            st.rerun()
    with ex_col2:
        if st.button("⚠️ 可疑子域名", use_container_width=True):
            st.session_state.example_url = "https://secure-taiwanbank-login.com/verify"
            st.rerun()
    with ex_col3:
        if st.button("🚨 高風險（IP + 長URL）", use_container_width=True):
            st.session_state.example_url = "http://203.0.113.45/login/verify?account=update&session=xyz9876543210"
            st.rerun()
    
    if 'example_url' in st.session_state:
        url_input = st.session_state.example_url
        del st.session_state.example_url
    
    if analyze_btn or url_input:
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input
        
        # 簡單規則分析
        reasons = []
        risk_score = 0
        
        # 規則 1: 長度
        if len(url_input) > 80:
            reasons.append(("URL 過長（>80 字元）", "+25", "釣魚網站常使用長 URL 隱藏真實目的地"))
            risk_score += 25
        
        # 規則 2: IP 地址
        if re.search(r'\d+\.\d+\.\d+\.\d+', url_input):
            reasons.append(("使用 IP 地址而非域名", "+30", "合法銀行幾乎不會直接使用 IP"))
            risk_score += 30
        
        # 規則 3: 品牌名稱出現在子域名
        brands = ['taiwanbank', 'cathay', 'esun', 'fubon', 'line', 'shopee', 'pchome']
        for brand in brands:
            if brand in url_input.lower() and not url_input.lower().startswith(f'https://{brand}'):
                reasons.append((f"品牌名稱 '{brand}' 出現在非主域名位置", "+20", "常見 typosquatting / 子域名偽造"))
                risk_score += 20
                break
        
        # 規則 4: HTTPS 缺失
        if url_input.startswith('http://'):
            reasons.append(("使用不安全的 HTTP（非 HTTPS）", "+15", "現代合法金融服務幾乎強制 HTTPS"))
            risk_score += 15
        
        # 規則 5: 敏感關鍵字
        sensitive = ['login', 'verify', 'secure', 'update', 'account', 'confirm']
        found_keywords = [k for k in sensitive if k in url_input.lower()]
        if found_keywords:
            reasons.append((f"路徑包含敏感關鍵字：{', '.join(found_keywords)}", "+10", "釣魚頁面常用 urgency 相關詞彙"))
            risk_score += 10
        
        risk_score = min(risk_score, 100)
        
        # 顯示結果
        st.divider()
        colA, colB = st.columns([1, 2])
        
        with colA:
            if risk_score >= 70:
                st.error(f"🚨 高風險釣魚網站（{risk_score}/100）")
            elif risk_score >= 40:
                st.warning(f"⚠️ 中等風險（{risk_score}/100）")
            else:
                st.success(f"✅ 風險較低（{risk_score}/100）")
            
            st.metric("風險分數", f"{risk_score}/100")
        
        with colB:
            if reasons:
                st.write("**判斷理由：**")
                for reason, score, explanation in reasons:
                    st.markdown(f"- **{reason}** `{score}`\n  <span style='color:#666; font-size:0.85em'>{explanation}</span>", unsafe_allow_html=True)
            else:
                st.info("未觸發明顯高風險規則，但仍建議人工複核域名拼寫。")
        
        st.caption("以上為簡易規則判斷。真實系統會結合機器學習模型與即時威脅情資。")

with tab2:
    st.subheader("AI 協作 Prompt 展示（學生可直接複製使用）")
    st.info("下方為本報告撰寫時實際使用的 Prompt 範例。學生可複製到 Grok / ChatGPT / Claude 使用，並要求輸出繁體中文。")
    
    with st.expander("Prompt 1：生成釣魚網站 HTML Demo（教育版）"):
        st.code("""You are an expert information security educator for an Introduction to Computer Science course in Taiwan. 
Create a complete, single-file HTML educational demo that simulates a phishing website attack on a Taiwanese bank login page.

Requirements:
- Strong, visible disclaimers that this is 100% educational and simulated
- Split-screen layout: Victim view (realistic login form) + Attacker dashboard (real-time captured credentials)
- JavaScript that captures form data locally and displays it instantly in the attacker panel
- "View source explanation" modal showing how easy it is for attackers to clone pages
- Integrated defense tips
- Use Tailwind CSS via CDN for modern look
- All text in Traditional Chinese where appropriate for Taiwanese students
- Emphasize ethics and never encourage real attacks

Output only the complete HTML code.""", language="text")
    
    with st.expander("Prompt 2：分析可疑 URL 並給出教育性解釋"):
        st.code("""請以計算機概論學生的程度，用繁體中文詳細解釋為什麼以下 URL 可能是釣魚網站，並給出具體防禦建議：

https://taiwan-bank-login-secure-verify.com/update?session=abc123

請包含：
1. URL 結構分析（子域名、路徑、參數）
2. 常見社交工程心理手法
3. 與合法銀行的差異
4. 給非資安專家的實用檢查步驟""", language="text")