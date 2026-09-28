# การเทรนโมเดล Gen 3 บนเครื่องอื่น (โน้ตบุ๊ก)

เทรนบนเครื่อง local เท่านั้น — **ห้ามเทรนหรือติดตั้งอะไรบน VPS production** (ดู `WORKING_RULES.md`, `WAF_GEN3_ROADMAP.md`)
สถานะงานล่าสุดและงานที่ค้างอยู่: `PROGRESS_GEN3_CHECKPOINT.md`

## ไฟล์ที่ต้องมี (3 กลุ่ม)

| กลุ่ม | ได้มาจาก | อยู่ที่ |
| :--- | :--- | :--- |
| 1. โค้ด + เอกสาร + รายงานผลของ candidate (`ml/models/archive/**/*.json`) | `git checkout trainmodelgen3` | ใน repo |
| 2. Public dataset (~1.7 GB) | ดาวน์โหลดเองด้วยสคริปต์ (ตรวจ sha256) | `ml/dataset/external/`, `ml/dataset/csic_final.csv` |
| 3. ข้อมูลจาก VPS (~40 MB) | **คัดลอกเองแบบ private** — ห้ามขึ้น git เพราะเป็น traffic จริงจาก production | `ml/dataset/vps_audit_labelled.jsonl` (+ `.stats.json`), `ml/dataset/nginx_real_benign.jsonl`, `ml/telemetry/*.jsonl` |

ไฟล์โมเดล `.joblib` ของ candidate ไม่อยู่ใน git — สร้างใหม่ได้จากโค้ดและข้อมูลชุดเดียวกัน

## ขั้นตอน

```bash
git clone git@github.com:jakkaret/waf_project.git && cd waf_project
git checkout trainmodelgen3

python3.12 -m venv .venv
.venv/bin/pip install -r ml/requirements-train.txt

# กลุ่ม 3: แตกไฟล์ข้อมูล VPS ที่คัดลอกมา (สร้างจากเครื่องเดิมด้วยคำสั่งด้านล่าง)
tar -xzf waf_ml_private_data_<date>.tar.gz          # ได้ ml/dataset/*.jsonl และ ml/telemetry/

# กลุ่ม 2: ดาวน์โหลด open-appsec + SR-BH 2020 แล้วเตรียมข้อมูล (~3 นาที, RAM ~2.5 GB)
PYTHONPATH=. .venv/bin/python ml/prepare_external_datasets.py --download
# CSIC 2010 ถูกดาวน์โหลดอัตโนมัติตอนเทรนครั้งแรก

# เทรน + ประเมิน (ครั้งแรกสร้าง dataset ~6 นาที แล้วเก็บ cache ใน ml/dataset/.build_cache/)
PYTHONPATH=. .venv/bin/python ml/train_gen3_full_real_benchmark.py
PYTHONPATH=. .venv/bin/python ml/check_overfitting.py
PYTHONPATH=. .venv/bin/python ml/test_comprehensive.py
PYTHONPATH=. .venv/bin/python ml/evaluate_leave_source_out.py
PYTHONPATH=. .venv/bin/python -m pytest ml/tests ml/test_feature_engineering.py -q
```

สร้างไฟล์ข้อมูล VPS (กลุ่ม 3) จากเครื่องที่มีข้อมูลอยู่แล้ว:

```bash
tar -czf ~/waf_ml_private_data_$(date +%Y%m%d).tar.gz \
    ml/dataset/vps_audit_labelled.jsonl ml/dataset/vps_audit_labelled.stats.json \
    ml/dataset/nginx_real_benign.jsonl ml/telemetry
```

หรือดึง audit log ใหม่จาก VPS แบบอ่านอย่างเดียว (ไม่เขียนไฟล์บน VPS):

```bash
ssh root@178.104.53.123 python3 - < scripts/extract_vps_audit_dataset.py > ml/dataset/vps_audit_labelled.jsonl
```

## เทรนบน Google Colab

เปิด `ml/waf_gen3_colab.ipynb` ใน Colab (File → Open notebook → GitHub → branch `trainmodelgen3`) แล้วรันตามลำดับ cell:
repo private ให้เพิ่ม Colab Secret `GITHUB_TOKEN` (fine-grained, Contents: read); ข้อมูล VPS (กลุ่ม 3) ใส่เป็น tar.gz ใน
`MyDrive/waf_ml/private/` เฉพาะเมื่อได้รับอนุญาตให้เก็บบน Google Drive — ถ้าไม่มี notebook จะรันด้วย public data อย่างเดียว.
Dataset, build cache และโมเดล `.joblib` เก็บใน `MyDrive/waf_ml/`; ผล (JSON + log) ดาวน์โหลดเป็น zip แล้วแตกที่ root ของ repo

## ความต้องการของเครื่อง

- Python 3.12, RAM ≥ 8 GB (peak ~3 GB ตอนสร้าง dataset), ดิสก์ว่าง ≥ 6 GB
- ตัวเทรนใช้ `n_jobs = จำนวน core จริง` (ใช้ hyperthread ทั้งหมดแล้วช้าลง ~8 เท่าใน WSL)
- ตัวเลขที่ได้ควรตรงกับ `ml/models/archive/<candidate>/experiment_report.json` ถ้าใช้ข้อมูลชุดเดียวกัน — ตรวจ `dataset_manifest.json` (sha256 ของไฟล์ input ทุกไฟล์)
