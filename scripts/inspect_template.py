import os
import sys
import zipfile
import xml.etree.ElementTree as ET

try:
    import pptx
    from pptx import Presentation
except ImportError:
    pptx = None

def inspect_with_pptx(path: str):
    if not pptx:
        print("python-pptx not installed")
        return
    if not os.path.exists(path):
        print(f"Path not found: {path}")
        return
    prs = Presentation(path)
    print(f"Slide width: {prs.slide_width.inches} in, height: {prs.slide_height.inches} in")
    print(f"Total slides: {len(prs.slides)}\n")
    for i, slide in enumerate(prs.slides):
        print(f"==================== SLIDE {i+1} ====================")
        for j, shape in enumerate(slide.shapes):
            print(f"  Shape {j+1}: type={shape.shape_type}, name='{shape.name}'")
            if shape.has_text_frame:
                for p in shape.text_frame.paragraphs:
                    txt = p.text.strip()
                    if txt:
                        print(f"    Text: {txt}")

def inspect_with_zip(pptx_path: str):
    if not os.path.exists(pptx_path):
        print(f"File not found: {pptx_path}")
        return
    with zipfile.ZipFile(pptx_path) as z:
        for i in range(1, 11):
            slide_file = f'ppt/slides/slide{i}.xml'
            if slide_file not in z.namelist():
                continue
            tree = ET.fromstring(z.read(slide_file))
            rels_name = f'ppt/slides/_rels/slide{i}.xml.rels'
            rels = z.read(rels_name).decode('utf-8') if rels_name in z.namelist() else ''
            imgs = [line for line in rels.split('\n') if 'image' in line]
            shapes = tree.findall('.//{http://schemas.openxmlformats.org/presentationml/2006/main}sp')
            tables = tree.findall('.//{http://schemas.openxmlformats.org/drawingml/2006/main}tbl')
            print(f'Slide {i}: {len(shapes)} shapes, {len(tables)} tables, {len(imgs)} images')
            texts = [
                ''.join(p.itertext()).strip()
                for p in tree.iter('{http://schemas.openxmlformats.org/drawingml/2006/main}p')
                if ''.join(p.itertext()).strip()
            ]
            print('  Preview: ' + ' | '.join(texts[:4]))

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'report_template.docx'
    print(f"Inspecting {target}...")
