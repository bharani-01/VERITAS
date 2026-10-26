import zipfile
import xml.etree.ElementTree as ET

pptx_path = r'c:\Users\Swaminathan\Downloads\NetGuard_Project_Presentation.pptx'
z = zipfile.ZipFile(pptx_path)

for i in range(2, 11):
    print(f"\n==================== SLIDE {i} ====================")
    tree = ET.fromstring(z.read(f'ppt/slides/slide{i}.xml'))
    rels_name = f'ppt/slides/_rels/slide{i}.xml.rels'
    rels = z.read(rels_name).decode('utf-8') if rels_name in z.namelist() else ''
    
    # Print slide title or top header
    for sp in tree.findall('.//{http://schemas.openxmlformats.org/presentationml/2006/main}sp'):
        txt = ''.join(sp.itertext()).strip()
        xfrm = sp.find('.//{http://schemas.openxmlformats.org/drawingml/2006/main}xfrm')
        off = xfrm.find('{http://schemas.openxmlformats.org/drawingml/2006/main}off') if xfrm is not None else None
        ext = xfrm.find('{http://schemas.openxmlformats.org/drawingml/2006/main}ext') if xfrm is not None else None
        pos = f"x={off.get('x')} y={off.get('y')} w={ext.get('cx')} h={ext.get('cy')}" if off is not None and ext is not None else "no pos"
        print(f"Shape [{pos}]: {txt[:120]}")
    for pic in tree.findall('.//{http://schemas.openxmlformats.org/presentationml/2006/main}pic'):
        blip = pic.find('.//{http://schemas.openxmlformats.org/drawingml/2006/main}blip')
        embed = blip.get('{http://schemas.openxmlformats.org/officeDocument/2006/relationships}embed') if blip is not None else 'no embed'
        xfrm = pic.find('.//{http://schemas.openxmlformats.org/drawingml/2006/main}xfrm')
        off = xfrm.find('{http://schemas.openxmlformats.org/drawingml/2006/main}off') if xfrm is not None else None
        ext = xfrm.find('{http://schemas.openxmlformats.org/drawingml/2006/main}ext') if xfrm is not None else None
        pos = f"x={off.get('x')} y={off.get('y')} w={ext.get('cx')} h={ext.get('cy')}" if off is not None and ext is not None else "no pos"
        print(f"Picture [{pos}] embed={embed}")
