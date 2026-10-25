import sys
import pptx
from pptx import Presentation

path = r'D:\College\Sem-5\Computer Network\CN-Project\Report\NetGuard_Project_Presentation.pptx'
prs = Presentation(path)

print(f"Slide width: {prs.slide_width.inches} in, height: {prs.slide_height.inches} in")
print(f"Total slides: {len(prs.slides)}\n")

for i, slide in enumerate(prs.slides):
    print(f"==================== SLIDE {i+1} ====================")
    # Background info
    bg = slide.background
    try:
        fill = bg.fill
        print(f"Background fill type: {fill.type}")
    except Exception as e:
        print(f"Background: {e}")
        
    for j, shape in enumerate(slide.shapes):
        shape_desc = f"  Shape {j+1}: type={shape.shape_type}, name='{shape.name}', left={round(shape.left.inches, 2)}, top={round(shape.top.inches, 2)}, w={round(shape.width.inches, 2)}, h={round(shape.height.inches, 2)}"
        
        # Check fill color
        try:
            if shape.fill and shape.fill.type:
                if shape.fill.type == 1: # solid
                    shape_desc += f", fill={shape.fill.fore_color.rgb}"
        except:
            pass

        print(shape_desc)
        
        if shape.has_text_frame:
            tf = shape.text_frame
            for p_idx, p in enumerate(tf.paragraphs):
                p_text = p.text.strip()
                if p_text:
                    font_name = p.font.name if p.font else None
                    font_size = p.font.size.pt if (p.font and p.font.size) else None
                    font_bold = p.font.bold if p.font else None
                    font_color = None
                    try:
                        if p.font and p.font.color and p.font.color.rgb:
                            font_color = str(p.font.color.rgb)
                    except:
                        pass
                    
                    runs_info = []
                    for r in p.runs:
                        r_font = r.font.name if r.font else None
                        r_size = r.font.size.pt if (r.font and r.font.size) else None
                        r_col = None
                        try:
                            if r.font and r.font.color and r.font.color.rgb:
                                r_col = str(r.font.color.rgb)
                        except:
                            pass
                        runs_info.append(f"run('{r.text[:30]}', font={r_font}, size={r_size}, col={r_col})")
                    
                    print(f"    P{p_idx+1}: '{p_text}' [font={font_name}, sz={font_size}, b={font_bold}, col={font_color}]")
                    if runs_info and (not font_name or not font_size):
                        print(f"       Runs: {', '.join(runs_info[:3])}")
                        
        if shape.has_table:
            t = shape.table
            print(f"    TABLE: {len(t.rows)} rows x {len(t.columns)} cols")
            for r_i, row in enumerate(t.rows):
                row_txt = [c.text.strip().replace('\n', ' ') for c in row.cells]
                print(f"      Row {r_i+1}: {row_txt}")

    # Check notes
    if slide.has_notes_slide:
        notes = slide.notes_slide.notes_text_frame.text.strip()
        if notes:
            print(f"  NOTES: {notes[:100]}...")
    print()
