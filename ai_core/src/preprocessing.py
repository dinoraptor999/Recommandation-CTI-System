# ai_core/src/preprocess.py
import os
import pdfplumber
import re
from langchain.text_splitter import RecursiveCharacterTextSplitter

def extract_text_from_pdf(pdf_path):
    """Trích xuất văn bản thô từ file PDF."""
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
    """Làm sạch văn bản: Xóa header/footer rác, xuống dòng thừa, ký tự lạ."""
    # Ví dụ: Xóa các dòng chỉ chứa số trang (kiểu "Page 1 of 10")
    text = re.sub(r'Page \d+ of \d+', '', text)
    # Xóa khoảng trắng thừa và xuống dòng quá nhiều
    text = re.sub(r'\n\s*\n', '\n\n', text) 
    text = text.strip()
    return text

def chunk_text(text, chunk_size=1000, chunk_overlap=200):
    """Cắt văn bản thành các đoạn nhỏ (Chunks) cho LLM."""
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        separators=["\n\n", "\n", " ", ""]
    )
    chunks = text_splitter.split_text(text)
    return chunks

if __name__ == "__main__":
    # Test thử với file PDF giả (Bạn hãy tạo thủ công 1 file text nhỏ để test)
    print("Module Preprocessing đã sẵn sàng. Hãy bỏ file PDF vào thư mục data/raw_pdfs/ và chạy lại file này để test.")