import streamlit as st
from ti_oracle import lookup_ioc
from sigma_generator import generate_sigma
from intelfusion import run_intelfusion
from components.langchain_integration import ask_naradmuni
from PIL import Image
# ----------------- Page Setup -----------------
st.set_page_config(page_title="NaradMuni AI", layout="wide")


col1, col2, col3 = st.columns([2, 3, 2])
with col2:
    import os
    logo_path = "NaradMuni_Logo.png"
    if os.path.exists(logo_path):
        st.image(Image.open(logo_path), width=100, use_container_width=False)
    else:
        st.warning("Logo image not found. Please check the filename and path.")
    st.markdown('<h1 style="text-align:center; color:#38bdf8;">NaradMuni AI</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align:center; color:#cbd5e1;">Your AI Assistant for Threat Hunting & Threat Intelligence</p>', unsafe_allow_html=True)
    st.markdown('<p style="text-align:center; font-size:0.9rem; color:#64748b;">⚡ Powered by <a href="https://cyrac.in" target="_blank" style="color:#38bdf8;">CyRAC.in</a></p>', unsafe_allow_html=True)

# Custom CSS styling
st.markdown("""
    <style>
    body, .main, .block-container {
        background-color: #0f111a;
        color: #e2e8f0;
    }
    .block-container {
        padding: 2rem 3rem;
    }
    .info-box {
        background-color: #1a1c29;
        padding: 2rem;
        border-radius: 16px;
        border: 1px solid #2e2e3c;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
        margin-bottom: 2.5rem;
    }
    .stButton>button {
        background-color: #4338ca;
        color: white;
        border-radius: 8px;
        font-weight: 600;
    }
    .stButton>button:hover {
        background-color: #6366f1;
        transition: 0.3s ease;
    }
    .typing {
        display: inline-block;
        width: 1em;
        height: 1em;
        border-radius: 50%;
        background: #38bdf8;
        animation: blink 1.4s infinite ease-in-out both;
    }
    @keyframes blink {
        0%, 80%, 100% {
            transform: scale(0);
        } 40% {
            transform: scale(1);
        }
    }
    a {
        color: #38bdf8;
        text-decoration: none;
    }
    a:hover {
        text-decoration: underline;
    }
    h1, h2, h3, h4 {
        color: #38bdf8;
    }
    </style>
""", unsafe_allow_html=True)


# ----------------- App UI -----------------

# About section (centered, below logo/heading)
st.markdown('''
    <div style="text-align: center; padding: 1rem 0 2rem;">
        <p style="max-width: 800px; margin: auto; color: #94a3b8; font-size: 1.1rem; line-height: 1.6;">
            <b>About NaradMuni AI:</b> NaradMuni AI is a cyber threat hunting assistant that helps analysts enrich IOCs, generate Sigma rules,
            and answer threat intel queries using real-time AI-powered knowledge. Whether you’re a blue teamer or researcher, 
            NaradMuni accelerates your detection workflows with automation and insight.
        </p>
    </div>
''', unsafe_allow_html=True)

tabs = st.tabs(["🧠 TI-Oracle", "⚙️ SIGMapper", "🧩 IntelFusion", "💬 Ask NaradMuni"])

with tabs[0]:
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("🔍 TI-Oracle – Enrich IP, Domain, or File Hash")
    ioc = st.text_input("Enter an IOC (IP / Domain / File Hash):")
    if st.button("🔎 Lookup"):
        if ioc:
            result = lookup_ioc(ioc)
            if "error" in result:
                st.error(result["error"])
            else:
                st.success("Enrichment Result:")
                st.json(result)
        else:
            st.warning("Please enter an IOC.")
    st.markdown("</div>", unsafe_allow_html=True)

with tabs[1]:
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("⚙️ SIGMapper – Generate Detection Rules from Use Case")
    use_case = st.text_area("Describe the detection idea:", "Example: Detect PowerShell download using encoded command")
    technique = st.text_input("MITRE ATT&CK Technique ID (optional):", "T1059.001")
    if st.button("⚙️ Generate Sigma Rule"):
        if use_case:
            sigma_rule = generate_sigma(use_case, technique)
            st.success("Generated Sigma Rule:")
            st.code(sigma_rule, language="yaml")
        else:
            st.warning("Please describe a use case to generate a rule.")
    st.markdown("</div>", unsafe_allow_html=True)

with tabs[2]:
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("🧩 IntelFusion – Multi-Source IOC Enrichment")
    ioc = st.text_input("Enter an IP for enrichment (AbuseIPDB + OTX):")
    if st.button("🚀 Run IntelFusion"):
        if ioc:
            result = run_intelfusion(ioc)
            if result:
                st.success("Enrichment Results:")
                st.json(result)
            else:
                st.warning("No results returned.")
        else:
            st.warning("Please enter an IOC.")
    st.markdown("</div>", unsafe_allow_html=True)

with tabs[3]:
    st.markdown('<div class="info-box">', unsafe_allow_html=True)
    st.subheader("💬 Ask NaradMuni – Threat Intel Chatbot")
    user_question = st.text_input("Ask a threat-related question (e.g. How do I detect Cobalt Strike?)")
    if st.button("🧠 Get Answer"):
        if user_question:
            st.markdown('<div class="typing"></div>', unsafe_allow_html=True)
            with st.spinner("NaradMuni is thinking..."):
                response = ask_naradmuni(user_question)
            st.success("NaradMuni Says:")
            st.markdown(response)
        else:
            st.warning("Please enter a question.")
    st.markdown("</div>", unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown('<div style="text-align:center; font-size: 0.85rem; color: #aaa;">🔗 Connect with me: <a href="https://www.linkedin.com/in/cbbobhate" target="_blank">linkedin.com/in/cbbobhate</a></div>', unsafe_allow_html=True)