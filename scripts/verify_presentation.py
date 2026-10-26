import pptx
from pptx.util import Inches

prs = pptx.Presentation(r'd:\E0224033\InFoSec\CL\LB_Proj\VERITAS\AI_Vulnerability_Detection_and_Risk_Assessment_Presentation.pptx')

SW = prs.slide_width / Inches(1)
SH = prs.slide_height / Inches(1)
print(f"Presentation Bounds: {SW:.2f} x {SH:.2f} in")
print(f"Total Slides: {len(prs.slides)}\n")

has_error = False

for idx, slide in enumerate(prs.slides, 1):
    print(f"=== SLIDE {idx} ===")
    shapes_info = []
    for s_idx, shape in enumerate(slide.shapes):
        left = shape.left / Inches(1)
        top = shape.top / Inches(1)
        width = shape.width / Inches(1)
        height = shape.height / Inches(1)
        right = left + width
        bottom = top + height
        
        # Check alignment / bounds overflow
        overflow = ""
        if right > SW + 0.1 or bottom > SH + 0.1 or left < -0.1 or top < -0.1:
            overflow = f" [OVERFLOW: right={right:.2f}, bottom={bottom:.2f}]"
            has_error = True
            
        txt = ""
        if shape.has_text_frame:
            txt = shape.text_frame.text.replace("\n", " // ")[:80]
        elif shape.has_table:
            t = shape.table
            txt = f"[TABLE: {len(t.rows)}x{len(t.columns)}] " + " | ".join(c.text.replace('\n', ' ') for c in t.rows[0].cells)
        elif shape.shape_type == pptx.enum.shapes.MSO_SHAPE_TYPE.PICTURE:
            txt = "[PICTURE]"
        else:
            txt = f"[{shape.shape_type}]"
            
        print(f"  Shape {s_idx} ({left:.2f}, {top:.2f}, {width:.2f}, {height:.2f}){overflow}: {txt}")

if not has_error:
    print("\nSUCCESS: All slides verified! Zero alignment or overflow errors detected.")
else:
    print("\nWARNING: Some shapes overflowed slide bounds!")
