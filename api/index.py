from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse
import joblib
from google import genai
from google.genai import types
from PIL import Image
import io
import os
import json
import time

app = FastAPI()

# 1. Serve Frontend
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    with open("public/index.html", "r", encoding="utf-8") as f:
        return f.read()

# 2. Load Model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_model.pkl')
model = joblib.load(MODEL_PATH)

# 3. Feature Extraction
def extract_features(url):
    return [
        len(url), url.count('.'), url.count('-'),                             
        1 if 'http://' in url else 0, 1 if '.top' in url or '.xyz' in url else 0  
    ]

# --- NEW: Exponential Backoff Retry Logic ---
def call_gemini_with_retry(client, model_name, contents, config, max_retries=3):
    for attempt in range(max_retries):
        try:
            return client.models.generate_content(
                model=model_name, 
                contents=contents,
                config=config
            )
        except Exception as e:
            # If it's a 503 error and we haven't run out of retries, wait and try again
            if "503" in str(e) and attempt < max_retries - 1:
                time.sleep(2 ** attempt) # Waits 1s, then 2s, then 4s
                continue
            raise e # If it's a different error or we are out of retries, crash normally
# --------------------------------------------

# 4. Updated API Endpoint
@app.post("/api/analyze_smishing")
async def analyze_smishing(file: UploadFile = File(None), text_input: str = Form(None)):
    try:
        if not file and not text_input:
            return {"error": "Please provide either an image or paste text/URL."}

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return {"error": "API Key is missing! Please set GEMINI_API_KEY."}
            
        client = genai.Client(api_key=api_key)
        
        config = types.GenerateContentConfig(
            automatic_function_calling={"disable": True}
        )
        
        # A. Decide whether to read an image or read text
        if file and file.filename != "":
            image_data = await file.read()
            image = Image.open(io.BytesIO(image_data))
            prompt = """Look at this screenshot of an SMS message. 
            Extract the exact URL link present. Also extract the full text message.
            Return ONLY a valid JSON format like this: {"url": "extracted_url", "message": "extracted_message"}
            Do not add markdown formatting or the word json."""
            
            response = call_gemini_with_retry(client, 'gemini-3.6-flash', [prompt, image], config)
        else:
            prompt = f"""Analyze the following input: "{text_input}"
            If it contains a URL, extract it. If it is just a URL, extract it. 
            Extract the surrounding message if there is one.
            Return ONLY a valid JSON format like this: {{"url": "extracted_url", "message": "extracted_message"}}
            Do not add markdown formatting or the word json."""
            
            response = call_gemini_with_retry(client, 'gemini-3.6-flash', [prompt], config)
        
        # B. Clean and Parse JSON
        response_text = response.text.strip().replace('```json', '').replace('```', '')
        extracted_data = json.loads(response_text)
        
        url = extracted_data.get("url", "")
        message = extracted_data.get("message", "")

        if not url:
            return {"error": "No URL found in the provided input. Are you sure it contains a link?"}

        # C. Run Machine Learning Model
        features = [extract_features(url)]
        is_malicious = bool(model.predict(features)[0])
        
        # D. Generate AI Forensics Report
        report = "Safe link detected. No threat found."
        if is_malicious:
            report_prompt = f"""Act as a cybersecurity analyst. Explain why this SMS message and URL are a phishing scam.
            Message: "{message}"
            URL: "{url}"
            Write a short, professional, 3-sentence threat report explaining the psychological tactics and technical URL red flags."""
            
            report_response = call_gemini_with_retry(client, 'gemini-3.6-flash', [report_prompt], config)
            report = report_response.text

        return {
            "url": url,
            "message": message,
            "is_malicious": is_malicious,
            "report": report
        }
        
    except Exception as e:
        return {"error": f"Something went wrong: {str(e)}"}