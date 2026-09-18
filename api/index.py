from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import JSONResponse
from google import genai
from google.genai import types
import os
import re
import joblib

app = FastAPI()

# Initialize the Gemini AI client
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# Safely attempt to load the Random Forest ML Model as a backup layer
try:
    # Looks for the model in the parent directory's 'model' folder
    model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'model', 'phishing_model.pkl')
    ml_model = joblib.load(model_path)
except Exception:
    ml_model = None

@app.post("/api/analyze_smishing")
async def analyze_smishing(file: UploadFile = File(None), text_input: str = Form(None)):
    try:
        analyzed_text = ""
        
        # 1. Extract Text (Handle both Screenshot and Text inputs)
        if text_input:
            analyzed_text = text_input.strip()
        elif file:
            contents = await file.read()
            
            # REQUIRED FIX: Wrap the image bytes correctly for the new GenAI SDK
            image_part = types.Part.from_bytes(
                data=contents,
                mime_type=file.content_type
            )
            
            ocr_response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=[
                    image_part,
                    "Extract only the readable text from this image. Do not add any commentary."
                ]
            )
            analyzed_text = ocr_response.text.strip()

        if not analyzed_text:
            return JSONResponse({"error": "No text provided or found in the image."})

        # 2. Strict AI Evaluation Prompt
        prompt = f"""
        You are a cybersecurity expert analyzing an SMS or message for phishing/smishing.
        Message to analyze: "{analyzed_text}"
        
        Evaluate if this message is a genuine threat (trying to steal data, fake links, urgent scams) or completely safe (normal conversation, legit company alert without suspicious links).
        
        Write a 2-3 sentence threat report. 
        Then, on a NEW LINE at the very bottom, output EXACTLY ONE of these tags:
        [TAG: SAFE]
        [TAG: MALICIOUS]
        """

        # 3. Generate Report
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        result_text = response.text.strip()
        
        # 4. Determine Verdict (Default to Safe, prove it is Malicious)
        is_malicious = False
        
        if "[TAG: MALICIOUS]" in result_text.upper():
            is_malicious = True
            
        if ml_model is not None:
            try:
                prediction = ml_model.predict([analyzed_text])[0]
                if prediction == 1 or str(prediction).lower() == 'spam':
                    is_malicious = True
            except Exception:
                pass 

        # 5. Clean up data for the Frontend UI
        clean_report = result_text.replace("[TAG: MALICIOUS]", "").replace("[TAG: SAFE]", "").strip()
        
        urls = re.findall(r'(https?://[^\s]+)', analyzed_text)
        extracted_url = urls[0] if urls else "No link detected"

        return {
            "is_malicious": is_malicious,
            "url": extracted_url,
            "message": analyzed_text,
            "report": clean_report
        }

    except Exception as e:
        return JSONResponse({"error": f"Analysis failed: {str(e)}"}, status_code=500)
