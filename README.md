# 🛡️ PhishGuard Nexus: AI-Powered Recruitment Fraud Scanner

[![Hackathon - PromptWars x GenAI Club](https://img.shields.io/badge/Hackathon-PromptWars_x_GenAI_Club-blueviolet)](#)
[![Tech Stack - React + Vite](https://img.shields.io/badge/Tech_Stack-React_|_Vite_|_TS-blue)](#)
[![AI Engine - Gemini 2.5 Flash](https://img.shields.io/badge/AI_Engine-Gemini_2.5_Flash-orange)](#)
[![Deployment - Netlify](https://img.shields.io/badge/Deployed-Netlify-success)](#)

**PromptWars x GEN AI Club 2026** | **Track:** Fake Offer Letter & Phishing Inspector  
**Author:** Vinayak Rathod | Presidency University  

---

## 🚀 The Core Problem
Job seekers and renters are losing millions of dollars to sophisticated corporate impersonation schemes. Threat actors easily bypass standard email spam filters using fake appointment letters, pay-for-equipment phishing, and deposit traps. Traditional text-matching algorithms are failing against modern, AI-generated psychological coercion.

## 💡 The Solution: Cognitive Cybersecurity
**PhishGuard Nexus** is a deterministic, multi-modal AI verification engine. Instead of relying on static keyword blacklists, it acts as a forensic investigator that analyzes the **"Dark Triad" of Scam Psychology**:
1. **Urgency Tactics** ("Offer expires in 2 hours")
2. **Authority Abuse** (CEOs direct-messaging junior candidates on Telegram)
3. **Artificial Scarcity** ("Only 1 position left")

By parsing text, URLs, and UI screenshots, it calculates a dynamic **Scam Threat Index (0–100%)** in real-time.

---

## 🔥 Key Innovations & Features
* **Dynamic Threat Telemetry:** Calculates a real-time risk score alongside sub-scores for Financial Traps, Domain Integrity, and Psychological Coercion.
* **Multi-Modal Vision Ingestion:** Scammers embed text in PDFs or manipulated WhatsApp images to evade filters. Using Gemini 2.5 Flash, the system extracts and evaluates hidden threats directly from uploaded screenshots.
* **Live Domain Intelligence:** Simulates domain-age checks to instantly flag newly registered, typosquatted domains masquerading as Fortune 500 companies.
* **Strict JSON API Enforcement:** The core prompt enforces a strict JSON output schema, ensuring the frontend never breaks due to conversational AI hallucinations. 

---

## 🏗️ System Architecture
The application is engineered as a highly scalable, zero-latency Single-Page Application (SPA) utilizing a modern React and Vite architecture.

* **Frontend Framework:** React (TypeScript) via Vite.
* **Styling:** Tailwind CSS (`src/index.css`).
* **AI Engine:** Google Gemini API (`gemini-2.5-flash`).
* **Deployment:** Automated CI/CD via Netlify (`netlify.toml`, `public/_redirects`).
* **Security:** API keys are managed securely via environment variables and client-side vaulting (`.env.example`)[cite: 4]. Zero secrets are committed to this repository.

---

## 🛠️ Local Development Setup

To run this project locally for evaluation, follow these steps:

**1. Clone the repository**
```bash
git clone [https://github.com/RathodVinay/GEN-AI-x-Hack2Skill.git](https://github.com/RathodVinay/GEN-AI-x-Hack2Skill.git)
cd GEN-AI-x-Hack2Skill
