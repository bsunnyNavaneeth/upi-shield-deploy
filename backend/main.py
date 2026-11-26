import io
import os
import re
import warnings
import logging

logger = logging.getLogger("uvicorn.error")
import pytesseract
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, UnidentifiedImageError


app = FastAPI(title="UPI Shield Analysis API")

# CORS: list your deployed website(s) in ALLOWED_ORIGINS (comma-separated, no
# trailing slash). FRONTEND_ORIGIN is still read so older settings keep working.
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8080",
    "http://localhost:3000",
]
for var in ("ALLOWED_ORIGINS", "FRONTEND_ORIGIN"):
    for origin in os.getenv(var, "").split(","):
        origin = origin.strip().rstrip("/")
        if origin and origin not in allowed_origins:
            allowed_origins.append(origin)

# Optional: also allow Vercel preview/production URLs whose name starts with
# "upi-shield" (e.g. https://upi-shield-site-git-main-you.vercel.app).
origin_regex = os.getenv("ALLOWED_ORIGIN_REGEX", r"https://upi-shield[a-z0-9-]*\.vercel\.app")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=origin_regex or None,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_TEXT_LENGTH = 10000

# Limit image dimensions to reduce the risk of decompression bombs.
Image.MAX_IMAGE_PIXELS = 20_000_000

RULES = [
    (r"\b(otp|one[\s-]?time password)\b", 25, "The text mentions an OTP. Never share an OTP."),
    (r"\b(upi\s*pin|payment\s*pin)\b", 30, "The text mentions a UPI PIN. Never share your PIN."),
    (r"\b(urgent|immediately|act now|right now)\b", 15, "The message uses urgency or pressure."),
    (r"\b(blocked|suspended|account closure)\b", 15, "The message mentions account restrictions."),
    (r"\b(verify|verification|kyc)\b", 10, "The message asks for verification or KYC."),
    (r"\b(prize|lottery|cashback|reward|refund)\b", 15, "The message mentions a prize, reward, cashback, or refund."),
    (r"\b(anydesk|teamviewer|screen sharing|remote access)\b", 25, "The message mentions remote-access or screen-sharing tools."),
    (r"https?://\S+|www\.\S+", 10, "The text contains a link. Verify its destination independently."),
    (r"https?://\d{1,3}(?:\.\d{1,3}){3}", 20, "A link uses a numeric IP address instead of a normal website name."),
    (r"http://", 10, "A link does not use HTTPS."),
    (r"\b(receive|collect)\b.{0,40}\b(money|payment)\b.{0,60}\b(pin|scan|approve)\b", 20, "A request frames entering a PIN or scanning as a way to receive money."),
]


# Answer both GET and HEAD so Render's health checks succeed.
@app.api_route("/", methods=["GET", "HEAD"])
def health_check():
    return {"status": "ok", "service": "UPI Shield Analysis API"}


@app.post("/api/urls/analyze")
async def analyze(
    text: str = Form(default=""),
    file: UploadFile | None = File(default=None),
):
    text = text.strip()

    if len(text) > MAX_TEXT_LENGTH:
        raise HTTPException(status_code=400, detail="Text is too long. Maximum length is 10,000 characters.")

    extracted_text = ""

    if file is not None and file.filename:
        image_bytes = await file.read(MAX_FILE_SIZE + 1)

        if len(image_bytes) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="Image is too large. Maximum size is 5 MB.")
        if not image_bytes:
            raise HTTPException(status_code=400, detail="The uploaded image is empty.")

        try:
            # Convert Pillow's decompression-bomb warning into an error.
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(image_bytes)) as image:
                    if image.format not in {"PNG", "JPEG", "WEBP"}:
                        raise HTTPException(status_code=400, detail="Use a PNG, JPEG, or WebP image.")
                    image.load()
                    rgb_image = image.convert("RGB")
                    rgb_image.thumbnail((1600, 1600))

            extracted_text = pytesseract.image_to_string(rgb_image, timeout=45).strip()

        except HTTPException:
            raise
        except pytesseract.TesseractNotFoundError:
            raise HTTPException(status_code=503, detail="Screenshot reading is not available on this server right now.")
        except (UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning, OSError):
            raise HTTPException(status_code=400, detail="The image could not be processed.")
        except RuntimeError:
            raise HTTPException(status_code=503, detail="Image text extraction failed or timed out.")

        if not extracted_text:
            raise HTTPException(status_code=422, detail="No readable text was found in the image. Try a clearer screenshot.")

    combined_text = f"{text}\n{extracted_text}".strip()

    if not combined_text:
        raise HTTPException(status_code=400, detail="Provide text or an image to analyze.")

    score = 0
    indicators = []

    for pattern, points, explanation in RULES:
        if re.search(pattern, combined_text, flags=re.IGNORECASE | re.DOTALL):
            score += points
            indicators.append(explanation)

    score = min(score, 100)
    risk_level = "high" if score >= 70 else "medium" if score >= 40 else "low"

    if not indicators:
        indicators.append("No configured warning patterns were found. This does not mean the content is safe.")

    if extracted_text:
        indicators.insert(0, "The image was checked using text extraction. Visual elements and QR codes were not analyzed.")

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "summary": "Pattern check completed. The score is not a verified fraud probability.",
        "indicators": indicators,
    }
