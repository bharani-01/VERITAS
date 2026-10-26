import zipfile
import xml.etree.ElementTree as ET

pptx_path = r'c:\Users\Swaminathan\Downloads\NetGuard_Project_Presentation.pptx'
z = zipfile.ZipFile(pptx_path)

def inspect_slide_styles(slide_num):
    print(f"\n==================== STYLE OF SLIDE {slide_num} ====================")
    tree = ET.fromstring(z.read(f'ppt/slides/slide{slide_num}.xml'))
    for sp in tree.findall('.//{http://schemas.openxmlformats.org/presentationml/2006/main}sp'):
        txt = ''.join(sp.itertext()).strip()
        spPr = sp.find('{http://schemas.openxmlformats.org/presentationml/2006/main}spPr')
        fill = spPr.find('.//{http://schemas.openxmlformats.org/drawingml/2006/main}solidFill') if spPr is not None else None
        fill_clr = None
        if fill is not None:
            srgb = fill.find('{http://schemas.openxmlformats.org/drawingml/2006/main}srgbClr')
            scheme = fill.find('{http://schemas.openxmlformats.org/drawingml/2006/main}schemeClr')
            fill_clr = srgb.get('val') if srgb is not None else (scheme.get('val') if scheme is not None else 'other')
        
        ln = spPr.find('{http://schemas.openxmlformats.org/drawingml/2006/main}ln') if spPr is not None else None
        ln_clr = None
        if ln is not None:
            ln_fill = ln.find('.//{http://schemas.openxmlformats.org/drawingml/2006/main}solidFill')
            if ln_fill is not None:
                srgb = ln_fill.find('{http://schemas.openxmlformats.org/drawingml/2006/main}srgbClr')
                scheme = ln_fill.find('{http://schemas.openxmlformats.org/drawingml/2006/main}schemeClr')
                ln_clr = srgb.get('val') if srgb is not None else (scheme.get('val') if scheme is not None else 'other')
        
        # Check text colors and fonts
        runs = sp.findall('.//{http://schemas.openxmlformats.org/drawingml/2006/main}r')
        font_info = []
        for r in runs[:3]:
            rPr = r.find('{http://schemas.openxmlformats.org/drawingml/2006/main}rPr')
            if rPr is not None:
                sz = rPr.get('sz')
                b = rPr.get('b')
                r_fill = rPr.find('.//{http://schemas.openxmlformats.org/drawingml/2006/main}solidFill')
                r_clr = 'default'
                if r_fill is not None:
                    srgb = r_fill.find('{http://schemas.openxmlformats.org/drawingml/2006/main}srgbClr')
                    scheme = r_fill.find('{http://schemas.openxmlformats.org/drawingml/2006/main}schemeClr')
                    r_clr = srgb.get('val') if srgb is not None else (scheme.get('val') if scheme is not None else 'other')
                font_info.append(f"sz={sz} b={b} clr={r_clr}")
        
        print(f"Txt: {txt[:50]} | Fill: {fill_clr} | Line: {ln_clr} | Fonts: {font_info}")

inspect_slide_styles(2)
inspect_slide_styles(3)
inspect_slide_styles(6)
inspect_slide_styles(9)
inspect_slide_styles(10)
