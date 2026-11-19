import os
import re
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn, nsdecls

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    tcPr.append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>'))

def set_cell_margins(cell, top=120, bottom=120, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_table_borders(table, color="B0BEC5"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'  <w:top w:val="single" w:sz="6" w:space="0" w:color="{color}"/>'
        f'  <w:bottom w:val="single" w:sz="8" w:space="0" w:color="{color}"/>'
        f'  <w:insideH w:val="single" w:sz="4" w:space="0" w:color="{color}"/>'
        f'  <w:insideV w:val="single" w:sz="4" w:space="0" w:color="{color}"/>'
        f'  <w:left w:val="none"/>'
        f'  <w:right w:val="none"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)

def build_docx_from_markdown(md_path, docx_path):
    with open(md_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    doc = Document()

    # Standard A4 margins
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(0.6)

    # Base style
    style_normal = doc.styles['Normal']
    style_normal.font.name = 'Times New Roman'
    style_normal.font.size = Pt(12)
    style_normal.font.color.rgb = RGBColor(30, 30, 30)

    i = 0
    in_code_block = False
    code_lines = []

    while i < len(lines):
        line = lines[i].rstrip('\r\n')

        # Code blocks
        if line.startswith('```'):
            if in_code_block:
                in_code_block = False
                code_text = '\n'.join(code_lines)
                table = doc.add_table(rows=1, cols=1)
                table.alignment = WD_TABLE_ALIGNMENT.CENTER
                cell = table.cell(0, 0)
                set_cell_background(cell, "F4F6F9")
                set_cell_margins(cell, top=140, bottom=140, left=180, right=180)
                cp = cell.paragraphs[0]
                cp.paragraph_format.space_before = Pt(2)
                cp.paragraph_format.space_after = Pt(2)
                c_run = cp.add_run(code_text)
                c_run.font.name = 'Consolas'
                c_run.font.size = Pt(9.0)
                c_run.font.color.rgb = RGBColor(40, 44, 52)
                p_spacer = doc.add_paragraph()
                p_spacer.paragraph_format.space_before = Pt(2)
                p_spacer.paragraph_format.space_after = Pt(3)
                code_lines = []
            else:
                in_code_block = True
                code_lines = []
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        # Markdown tables
        if line.strip().startswith('|') and '|' in line.strip()[1:]:
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                table_lines.append(lines[i].strip())
                i += 1

            cleaned_rows = []
            for t_line in table_lines:
                cells = [c.strip() for c in t_line.strip('|').split('|')]
                if all(re.match(r'^:?-+:?$', c) for c in cells):
                    continue
                cleaned_rows.append(cells)

            if cleaned_rows:
                num_cols = max(len(r) for r in cleaned_rows)
                tbl = doc.add_table(rows=len(cleaned_rows), cols=num_cols)
                tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
                set_table_borders(tbl, "B0BEC5")

                for r_idx, r_data in enumerate(cleaned_rows):
                    row = tbl.rows[r_idx]
                    is_header = (r_idx == 0)
                    for c_idx in range(num_cols):
                        cell = row.cells[c_idx]
                        text_val = r_data[c_idx] if c_idx < len(r_data) else ""
                        # clean any raw math markers
                        text_val = text_val.replace('$', '')
                        set_cell_margins(cell, top=100, bottom=100, left=120, right=120)
                        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

                        if is_header:
                            set_cell_background(cell, "DCE4EC")
                        elif r_idx % 2 == 1:
                            set_cell_background(cell, "F8FAFC")

                        p = cell.paragraphs[0]
                        p.paragraph_format.space_before = Pt(2)
                        p.paragraph_format.space_after = Pt(2)
                        p.paragraph_format.line_spacing = 1.1
                        run = p.add_run(text_val)
                        run.font.name = 'Times New Roman'
                        run.font.size = Pt(9.5 if num_cols > 5 else 10.5)
                        if is_header:
                            run.bold = True
                            run.font.color.rgb = RGBColor(15, 30, 55)

                p_spacer = doc.add_paragraph()
                p_spacer.paragraph_format.space_before = Pt(2)
                p_spacer.paragraph_format.space_after = Pt(4)
            continue

        # Horizontal separator
        if line.strip() in ['---', '***', '___']:
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(4)
            i += 1
            continue

        # Title Page Headings
        if line.startswith('# ҚАЗАҚСТАН') or line.startswith('### АҚПАРАТТЫҚ') or line.startswith('### КОМПЬЮТЕРЛІК'):
            text = line.lstrip('#').strip()
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(4)
            run = p.add_run(text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(13)
            run.bold = True
            run.font.color.rgb = RGBColor(20, 35, 60)
            i += 1
            continue

        # Heading 1
        if line.startswith('# '):
            text = line[2:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(16)
            p.paragraph_format.space_after = Pt(6)
            p.paragraph_format.keep_with_next = True
            if "ПРАКТИКАЛЫҚ ЖҰМЫС" in text:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(16)
            run.bold = True
            run.font.color.rgb = RGBColor(20, 45, 80)
            i += 1
            continue

        # Heading 2
        if line.startswith('## '):
            text = line[3:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.keep_with_next = True
            if "Тақырыбы" in text:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(13.5)
            run.bold = True
            run.font.color.rgb = RGBColor(25, 55, 95)
            i += 1
            continue

        # Heading 3
        if line.startswith('### '):
            text = line[4:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(10)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(12)
            run.bold = True
            run.font.color.rgb = RGBColor(30, 65, 110)
            i += 1
            continue

        # Empty line
        if not line.strip():
            i += 1
            continue

        # Regular paragraph or list item
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.15

        stripped = line.strip()
        if stripped.startswith('- ') or stripped.startswith('* '):
            p.paragraph_format.left_indent = Inches(0.25)
            content = stripped[2:]
        elif re.match(r'^\d+\.\s', stripped):
            m = re.match(r'^(\d+\.)\s*(.*)$', stripped)
            p.paragraph_format.left_indent = Inches(0.25)
            content = f"{m.group(1)} {m.group(2)}"
        elif "Алматы, 2026" in stripped:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(14)
            content = stripped
        else:
            p.paragraph_format.first_line_indent = Inches(0.35)
            content = stripped

        # Clean math markers for clean Word look
        content = re.sub(r'\$([^$]+)\$', r'\1', content)

        # Parse inline formatting (bold, italic, code)
        parts = re.split(r'(\*\*.*?\*\*|\*.*?\*|`.*?`)', content)
        for part in parts:
            if not part:
                continue
            if part.startswith('**') and part.endswith('**'):
                r = p.add_run(part[2:-2])
                r.bold = True
            elif part.startswith('*') and part.endswith('*'):
                r = p.add_run(part[1:-1])
                r.italic = True
            elif part.startswith('`') and part.endswith('`'):
                r = p.add_run(part[1:-1])
                r.font.name = 'Consolas'
                r.font.size = Pt(10)
                r.font.color.rgb = RGBColor(160, 30, 30)
            else:
                r = p.add_run(part)
                r.font.name = 'Times New Roman'
                r.font.size = Pt(12)

        i += 1

    doc.save(docx_path)
    print(f"Successfully compiled: {docx_path}")

if __name__ == '__main__':
    md_in = r"d:\Diplom\docs\PRACTICAL_4_REPORT.md"
    docx_out = r"C:\Users\abdra\Desktop\ОНИРС4_жаңартылған.docx"
    build_docx_from_markdown(md_in, docx_out)
    
    # Try updating ОНИРС4.docx as well if unlocked
    try:
        import shutil
        shutil.copy2(docx_out, r"C:\Users\abdra\Desktop\ОНИРС4.docx")
        print("Also updated C:\\Users\\abdra\\Desktop\\ОНИРС4.docx")
    except Exception as e:
        print(f"Note: ОНИРС4.docx is currently locked in Word. Saved updated version as ОНИРС4_жаңартылған.docx ({e})")
