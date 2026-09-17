# PhishLens 🛡️
**An End-to-End AI/ML Smishing (SMS Phishing) Detection Pipeline**

PhishLens is a multi-modal cybersecurity forensics tool that analyzes screenshots of suspicious text messages. It uses Generative AI as an OCR to extract hidden URLs, classifies the URLs using a trained Machine Learning model, and generates explainable threat-intelligence reports.

## 🚀 Features
* **Multi-modal OCR:** Extracts raw text and URLs directly from SMS screenshots using Google Gemini 1.5 Flash.
* **Algorithmic Threat Detection:** Uses a custom-trained Random Forest Classifier (Scikit-Learn) to analyze URL features (length, TLDs, secure protocols) and predict malicious intent.
* **Explainable AI (XAI) Forensics:** Automatically generates a professional threat report explaining the psychological tactics and technical red flags found in the message.
* **Serverless Architecture:** Lightweight FastAPI backend designed for sub-60-second deployments on Vercel.

## 🛠️ Tech Stack
* **Frontend:** HTML5, CSS3, Vanilla JavaScript
* **Backend:** Python, FastAPI, Uvicorn
* **Machine Learning:** Scikit-Learn, Pandas, Joblib
* **Generative AI:** Google Gemini API (`google-genai`)
* **Deployment:** Vercel

## 💻 Local Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/PhishLens.git](https://github.com/your-username/PhishLens.git)
   cd PhishLens