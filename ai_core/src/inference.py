# ==========================================
# PHẦN 1: PREPROCESS (Gộp từ preprocess.py)
# ==========================================
import os
import re
import pdfplumber
#from langchain.text_splitter import RecursiveCharacterTextSplitter

def extract_text_from_pdf(pdf_path):
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"Không tìm thấy file: {pdf_path}")
    full_text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    full_text += text + "\n"
    except Exception as e:
        print(f"Lỗi khi parse PDF: {e}")
        return ""
    return full_text

def clean_text(text):
    text = re.sub(r'Page \d+ of \d+', '', text)
    text = re.sub(r'\n\s*\n', '\n\n', text)
    text = text.strip()
    return text

def chunk_text(text, chunk_size=1000, chunk_overlap=200):
    """Cắt văn bản thành các đoạn nhỏ bằng Python thuần (Không cần LangChain)."""
    chunks = []
    start = 0
    text_len = len(text)
    while start < text_len:
        end = min(start + chunk_size, text_len)
        # Tìm chỗ ngắt dòng hoặc khoảng trắng gần nhất để không cắt giữa chừng
        if end < text_len and text[end] not in ["\n", " "]:
            # Lùi về khoảng trắng gần nhất
            while end > start and text[end] not in ["\n", " "]:
                end -= 1
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start = end - chunk_overlap # Overlap giữa các đoạn
    return chunks

# ==========================================
# PHẦN 2: IOC EXTRACTION (Gộp từ extract_ioc.py)
# ==========================================
import ipaddress

def extract_ips(text):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    found = re.findall(ip_pattern, text)
    valid_ips = []
    for ip in found:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            continue
    return list(set(valid_ips))

def extract_domains(text):
    domain_pattern = r'\b([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)\b'
    found = re.findall(domain_pattern, text)
    domains = [match[0] for match in found]
    return list(set(domains))

def extract_hashes(text):
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    hashes = []
    hashes.extend(re.findall(md5_pattern, text))
    hashes.extend(re.findall(sha1_pattern, text))
    hashes.extend(re.findall(sha256_pattern, text))
    return list(set(hashes))

def extract_emails(text):
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    found = re.findall(email_pattern, text)
    return list(set(found))

def extract_all_iocs(text):
    return {
        "ips": extract_ips(text),
        "domains": extract_domains(text),
        "hashes": extract_hashes(text),
        "emails": extract_emails(text)
    }

# ==========================================
# PHẦN 3: INFERENCE (Phần chính)
# ==========================================
import json
import torch
from datetime import datetime
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

BASE_MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"
LORA_MODEL_PATH = r"C:\Users\hungm\cti-automation-project\ai_core\models\qwen-cti-lora-model"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

def load_model():
    print(f" Đang tải model lên {DEVICE}...")
    tokenizer = AutoTokenizer.from_pretrained(LORA_MODEL_PATH, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_NAME,
        torch_dtype=torch.float16 if DEVICE == "cuda" else torch.float32,
        device_map="auto" if DEVICE == "cuda" else None,
        trust_remote_code=True
    )
    model = PeftModel.from_pretrained(base_model, LORA_MODEL_PATH)
    if DEVICE == "cpu":
        model = model.to("cpu")
    model.eval()
    print(" Model đã sẵn sàng!")
    return model, tokenizer

def generate_prediction(model, tokenizer, input_text):
    prompt = f"""<|im_start|>system\nBạn là chuyên gia phân tích CTI.<|im_end|>\n<|im_start|>user\nPhân tích đoạn văn CTI sau và xác định MITRE ATT&CK ID, Tactic, và Evidence.\nInput: {input_text}<|im_end|>\n<|im_start|>assistant\n"""
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=200,
            temperature=0.1,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    assistant_output = response.split("<|im_start|>assistant\n")[-1].strip()
    try:
        start_idx = assistant_output.find('{')
        end_idx = assistant_output.rfind('}') + 1
        json_str = assistant_output[start_idx:end_idx]
        return json.loads(json_str)
    except:
        return {"error": "Không thể parse JSON từ AI output", "raw_output": assistant_output}

def process_pdf_report(pdf_path):
    print(f" Đang xử lý file: {pdf_path}")
    raw_text = extract_text_from_pdf(pdf_path)
    clean_raw_text = clean_text(raw_text)
    chunks = chunk_text(clean_raw_text)
    iocs = extract_all_iocs(clean_raw_text)
    best_chunk = chunks[0] if chunks else ""
    llm_result = generate_prediction(model, tokenizer, best_chunk)
    final_result = {
        "source_filename": os.path.basename(pdf_path),
        "analysis_timestamp": datetime.now().isoformat(),
        "technique_id": llm_result.get("technique_id", "N/A"),
        "tactic": llm_result.get("tactic", "N/A"),
        "technique_name": llm_result.get("technique_name", "N/A"),
        "evidence": llm_result.get("evidence", best_chunk[:300] + "..."),
        "confidence_score": 0.95,
        "iocs": iocs
    }
    return final_result

if __name__ == "__main__":
    model, tokenizer = load_model()
    test_text = "The attacker utilized PowerShell to download the payload from a remote server using Invoke-Expression."
    print(" Đang test AI với text mẫu...")
    result = generate_prediction(model, tokenizer, test_text)
    print(" Kết quả AI dự đoán:")
    print(json.dumps(result, indent=4, ensure_ascii=False))