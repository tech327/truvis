import fitz  


def extract_text_from_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    text_pages = []

    for page_num in range(len(doc)):
        page = doc.load_page(page_num)
        text = page.get_text()
        text_pages.append(text)

    return "\n".join(text_pages)


pdf_path = "uploaded_file.pdf"
text_content = extract_text_from_pdf(pdf_path)
print(text_content)
