import re
from pathlib import Path
from PIL import Image
import pytesseract
import pdfplumber

# If Tesseract isn't on PATH, set it here (uncomment and adjust path):
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

IP_RE   = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
LINE_OK = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}.*")
HTTP_HINTS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/1.", "HTTP/2")

def _ocr_image(path:str)->str:
    img = Image.open(path)
    return pytesseract.image_to_string(img)

def _ocr_pdf(path:str)->str:
    out=[]
    with pdfplumber.open(path) as pdf:
        for p in pdf.pages:
            out.append(p.extract_text() or "")
    return "\n".join(out)

def ocr_to_access_log(raw:str)->str:
    """
    Heuristic: keep lines that look like requests/IPs; drop empty garbage.
    Works well enough for demo & many real screenshots/PDFs.
    """
    lines=[]
    for ln in raw.splitlines():
        t = (ln or "").strip()
        if not t:
            continue
        if LINE_OK.search(t) or IP_RE.search(t) or any(h in t for h in HTTP_HINTS):
            lines.append(t)
    return "\n".join(lines)

def ocr_ingest_any(path:str)->str:
    ext = Path(path).suffix.lower()
    if ext in (".png",".jpg",".jpeg",".bmp",".tif",".tiff"):
        raw = _ocr_image(path)
    elif ext==".pdf":
        raw = _ocr_pdf(path)
    else:
        raise ValueError("Unsupported for OCR: provide image/pdf")
    return ocr_to_access_log(raw)
