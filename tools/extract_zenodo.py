#!/usr/bin/env python3
"""Verify the pinned ZIP and extract only the inputs needed by this repository."""
import argparse,hashlib,json,shutil,zipfile
from pathlib import Path

MEMBERS={
 'correct-dataset-train.json':'knowledge_extraction/CORRECT_database/processed_train_dataset.json',
 'correct-specifications-archive.json':'knowledge_extraction/output/vul_spec_train_merged.json',
 'primevul-contexts.json':'automatic_context_extraction_tool/primevul_with_context/primevul_zh_format_complete.json',
}
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--zip',required=True);p.add_argument('--output',required=True);a=p.parse_args()
h=hashlib.md5()
with open(a.zip,'rb') as f:
 for chunk in iter(lambda:f.read(8*1024*1024),b''):h.update(chunk)
if h.hexdigest()!='f00cffb93b05d263ad41060f597c8489':raise SystemExit('ZIP checksum does not match Zenodo record 17211934')
out=Path(a.output);out.mkdir(parents=True,exist_ok=True)
if any((out/name).exists() for name in MEMBERS):raise SystemExit('Output exists; choose a fresh extraction directory')
with zipfile.ZipFile(a.zip) as z:
 for name,member in MEMBERS.items():
  with z.open(member) as source,(out/name).open('wb') as dest:shutil.copyfileobj(source,dest)
print(json.dumps({'zip_md5':h.hexdigest(),'extracted':MEMBERS},indent=2))
