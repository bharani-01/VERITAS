import zipfile
import xml.etree.ElementTree as ET

pptx_path = r'c:\Users\Swaminathan\Downloads\NetGuard_Project_Presentation.pptx'
z = zipfile.ZipFile(pptx_path)

for i in range(1, 11):
    tree = ET.fromstring(z.read(f'ppt/slides/slide{i}.xml'))
    rels_name = f'ppt/slides/_rels/slide{i}.xml.rels'
    rels = z.read(rels_name).decode('utf-8') if rels_name in z.namelist() else ''
    imgs = [line for line in rels.split('\n') if 'image' in line]
    shapes = tree.findall('.//{http://schemas.openxmlformats.org/presentationml/2006/main}sp')
    tables = tree.findall('.//{http://schemas.openxmlformats.org/drawingml/2006/main}tbl')
    print(f'Slide {i}: {len(shapes)} shapes, {len(tables)} tables, {len(imgs)} images')

    texts = []
    for p in tree.iter('{http://schemas.openxmlformats.org/drawingml/2006/main}p'):
        t = ''.join(p.itertext()).strip()
        if t:
            texts.append(t)
    print('  Preview: ' + ' | '.join(texts[:4]))
