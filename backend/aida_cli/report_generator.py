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
    code_style = ParagraphStyle("AidaCode", fontName="Courier", fontSize=9, leading=12, spaceBefore=4, spaceAfter=4, leftIndent=20, rightIndent=20, backColor="#f5f5f5")

    md = markdown.Markdown(extensions=['tables', 'fenced_code', 'nl2br', 'def_list'])

    def parse_markdown_content(text: str) -> list:
        """Parse markdown text and return list of ReportLab elements"""
        elements = []
        html = md.convert(text or "")
        md.reset()
        
        lines = html.split('<br/>')
        in_code_block = False
        code_lines = []
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('<pre>') or line.startswith('<code>'):
                in_code_block = True
                code_content = line
                if '</code>' in line and '</pre>' in line:
                    code_text = line.replace('<pre>','').replace('</pre>','').replace('<code>','').replace('</code>','')
                    elements.append(Paragraph(code_text, code_style))
                    in_code_block = False
                continue
            
            if in_code_block:
                if '</code>' in line or '</pre>' in line:
                    code_text = line.replace('<pre>','').replace('</pre>','').replace('<code>','').replace('</code>','')
                    if code_text:
                        code_lines.append(code_text)
                    if code_lines:
                        elements.append(Paragraph('<br/>'.join(code_lines), code_style))
                    in_code_block = False
                    code_lines = []
                else:
                    clean_line = line.replace('<code>','').replace('</code>','')
                    code_lines.append(clean_line)
                continue
            
            if line.startswith('<h2>') or line.startswith('<h3>'):
                heading_text = line.replace('<h2>','').replace('</h2>','').replace('<h3>','').replace('</h3>','')
                elements.append(Paragraph(heading_text, heading_style))
            elif line.startswith('<ul>') or line.startswith('</ul>'):
                continue
            elif line.startswith('<li>'):
                item_text = line.replace('<li>','').replace('</li>','')
                item_text = item_text.replace('<p>','').replace('</p>','')
                elements.append(Paragraph(f"• {item_text}", normal_style))
            elif line.startswith('<p>'):
                p_text = line.replace('<p>','').replace('</p>','')
                if p_text:
                    elements.append(Paragraph(p_text, normal_style))
            elif line.startswith('<strong>') or line.startswith('<b>'):
                bold_text = line.replace('<strong>','').replace('</strong>','').replace('<b>','').replace('</b>','')
                elements.append(Paragraph(f"<b>{bold_text}</b>", normal_style))
            elif line.startswith('<table>'):
                table_lines = [line]
                j = lines.index(line)
                while j < len(lines) - 1 and '</table>' not in lines[j]:
                    j += 1
                    table_lines.append(lines[j])
                table_html = '<br/>'.join(table_lines)
                elements.extend(_parse_html_table(table_html, font_name))
            elif line.strip():
                elements.append(Paragraph(line, normal_style))
        
        return elements

    def _parse_html_table(html_table: str, fnt: str) -> list:
        from reportlab.platypus import Table, TableStyle
        from reportlab.lib import colors
        
        elements = []
        rows = []
        
        tr_pattern = r'<tr>(.*?)</tr>'
        td_pattern = r'<t[dh]>(.*?)</t[dh]>'
        
        import re
        for tr in re.finditer(tr_pattern, html_table, re.DOTALL):
            tr_content = tr.group(1)
            cells = re.findall(td_pattern, tr_content)
            if cells:
                row = []
                for cell in cells:
                    cell = cell.replace('<p>','').replace('</p>','')
                    row.append(cell)
                rows.append(row)
        
        if rows:
            col_widths = [None] * len(rows[0]) if rows else []
            table = Table(rows, colWidths=col_widths)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), fnt),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 10))
        
        return elements

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    elements = [Paragraph(title, title_style), Spacer(1, 8)]
    
    content_text = '<br/>'.join(lines)
    content_elements = parse_markdown_content(content_text)
    elements.extend(content_elements)
    
    doc.build(elements)
    return buffer.getvalue()
