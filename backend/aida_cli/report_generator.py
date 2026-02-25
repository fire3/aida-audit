import io
import os
import html


def _pdf_escape_text(s: str) -> str:
    if s is None:
        return ""
    s = str(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    try:
        s.encode("ascii")
    except Exception:
        s = "".join(ch if ord(ch) < 128 else "?" for ch in s)
    return s


def _make_pdf_pages(lines: list, page_width: int = 595, page_height: int = 842, margin: int = 40, line_height: int = 14):
    pages = []
    y_start = page_height - margin - 20
    y = y_start
    current_page = []
    for raw in lines:
        text = _pdf_escape_text(raw)
        if y < margin + 40:
            pages.append(current_page)
            current_page = []
            y = y_start
        current_page.append((margin, y, text))
        y -= line_height
    if current_page:
        pages.append(current_page)
    return pages


def _build_simple_pdf(lines: list, title: str = "AIDA Report"):
    page_width = 595
    page_height = 842
    margin = 40
    line_height = 14
    pages = _make_pdf_pages([f"{title}"] + [""] + lines, page_width=page_width, page_height=page_height, margin=margin, line_height=line_height)
    objects = []
    def add(obj):
        objects.append(obj)
        return len(objects)
    pages_obj_id = add(None)
    catalog_id = add(f"<< /Type /Catalog /Pages {pages_obj_id} 0 R >>")
    font_id = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    kids = []
    for page in pages:
        stream_lines = ["BT", "/F1 10 Tf"]
        for (x, y, text) in page:
            stream_lines.append(f"1 0 0 1 {x} {y} Tm ({text}) Tj")
        stream_lines.append("ET")
        stream_data = "\n".join(stream_lines).encode("latin-1", errors="ignore")
        contents_str = f"<< /Length {len(stream_data)} >>\nstream\n{stream_data.decode('latin-1', errors='ignore')}\nendstream"
        cid = add(contents_str)
        page_obj = f"<< /Type /Page /Parent {pages_obj_id} 0 R /MediaBox [0 0 {page_width} {page_height}] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {cid} 0 R >>"
        pid = add(page_obj)
        kids.append(pid)
    kids_str = "[ " + " ".join(f"{kid} 0 R" for kid in kids) + " ]"
    pages_obj = f"<< /Type /Pages /Kids {kids_str} /Count {len(kids)} >>"
    objects[pages_obj_id - 1] = pages_obj
    xref_positions = []
    out = []
    out.append("%PDF-1.4\n")
    for i, obj in enumerate(objects, start=1):
        xref_positions.append(sum(len(s.encode("latin-1")) for s in out))
        out.append(f"{i} 0 obj\n{obj}\nendobj\n")
    xref_start = sum(len(s.encode("latin-1")) for s in out)
    out.append("xref\n")
    out.append(f"0 {len(objects)+1}\n")
    out.append("0000000000 65535 f \n")
    for pos in xref_positions:
        out.append(f"{pos:010d} 00000 n \n")
    out.append("trailer\n")
    out.append(f"<< /Size {len(objects)+1} /Root {catalog_id} 0 R >>\n")
    out.append("startxref\n")
    out.append(f"{xref_start}\n")
    out.append("%%EOF\n")
    return "".join(out).encode("latin-1")


def build_reportlab_pdf(lines: list, title: str):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import markdown
    import logging

    font_name = "Helvetica"
    font_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "NotoSansSC-Regular.ttf"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "NotoSansSC-Regular.otf"),
    ]
    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont("NotoSansSC", font_path))
                font_name = "NotoSansSC"
                break
            except Exception as e:
                logging.getLogger(__name__).debug(f"Font load attempt failed: {e}")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("AidaTitle", parent=styles["Title"], fontName=font_name, fontSize=18, leading=22, spaceAfter=12)
    heading_style = ParagraphStyle("AidaHeading", parent=styles["Heading2"], fontName=font_name, fontSize=13, leading=16, spaceBefore=10, spaceAfter=6)
    normal_style = ParagraphStyle("AidaNormal", parent=styles["BodyText"], fontName=font_name, fontSize=10.5, leading=14)
    code_style = ParagraphStyle("AidaCode", fontName="Courier", fontSize=9, leading=12, spaceBefore=4, spaceAfter=4, leftIndent=20, rightIndent=20)

    def render_markdown(text: str) -> str:
        if not text:
            return ""
        md = markdown.Markdown(extensions=['nl2br', 'sane_lists'])
        html_text = md.convert(text or "")
        return html_text.replace("<br />", "<br/>").replace("<p>", "").replace("</p>", "<br/>")

    def to_paragraph_text(text: str):
        escaped = html.escape(text or "")
        return escaped.replace("\n", "<br/>")

    def is_markdown_block(line: str) -> bool:
        return any(line.startswith(m) for m in ["```", "##", "- [ ]", "- [x]", "|", "```python", "```c", "```bash"])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    elements = [Paragraph(to_paragraph_text(title), title_style), Spacer(1, 8)]
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        if line.startswith("=== "):
            elements.append(Paragraph(to_paragraph_text(line.replace("=== ", "").strip()), heading_style))
        
        elif line.startswith("- ") and i + 1 < len(lines) and lines[i + 1].startswith("  "):
            bullet_text = "• " + line[2:]
            meta_lines = []
            i += 1
            while i < len(lines) and lines[i].startswith("  "):
                meta_lines.append(lines[i].strip())
                i += 1
            if meta_lines:
                bullet_text += "<br/>" + "<br/>".join(html.escape(m) for m in meta_lines)
            elements.append(Paragraph(bullet_text, normal_style))
            continue
        
        elif line.strip() == "":
            elements.append(Spacer(1, 6))
        
        elif is_markdown_block(line):
            md_block = [line]
            i += 1
            while i < len(lines) and not lines[i].startswith("===") and not lines[i].startswith("- "):
                if lines[i].strip() == "" and i + 1 < len(lines) and not lines[i+1].startswith("  "):
                    break
                md_block.append(lines[i])
                i += 1
            md_text = "<br/>".join(html.escape(x) for x in md_block)
            elements.append(Paragraph(md_text, code_style))
            continue
        
        else:
            elements.append(Paragraph(to_paragraph_text(line), normal_style))
        
        i += 1
    
    doc.build(elements)
    return buffer.getvalue()
