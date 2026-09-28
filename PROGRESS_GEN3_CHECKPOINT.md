# WAF Gen 3 Development Checkpoint & Progress Status
**Date:** 2026-09-27 (21:11 ICT) — พักงานรอบที่ 2 (รอบแรก 16:56, เดิม 2026-09-25 13:10)  
**Branch:** `Backend`  
**Status:** ⏸️ **Hybrid candidate ผ่าน gate แบบ in-distribution แต่ยังไม่ควร promote — กำลังแก้ปัญหา payload ผูกกับบริบทของ dataset (context confounding)**

---

## 📍 จุดที่พักงานล่าสุด (27/09/2026 21:11)

### สถานะโดยย่อ
| หัวข้อ | สถานะ |
| :--- | :--- |
| ข้อมูลใหม่ (ของจริงทั้งหมด มี provenance) | ✅ VPS audit log ทั้ง 3 ไฟล์ + open-appsec + SR-BH 2020 → **417,972 แถว = 226,542 รูปแบบ** (เดิม ~9,900) |
| Candidate ล่าสุด | `ml/models/archive/task3-1-real-augmented-candidate-20260927-205652/` (`hybrid_waf_model.joblib` = token model + LightGBM) |
| Holdout CORE (CSIC + VPS, ถ่วงน้ำหนักตามรูปแบบ) | Benign **98.58%** / Attack **91.04%** ✅ ผ่าน gate (OOF 98.54% / 88.77%) |
| พร้อม promote หรือไม่ | ❌ **ยังไม่พร้อม** — มีจุดอ่อนเรื่องบริบท (ดูด้านล่าง) |
| Promotion / ขึ้น VPS | ❌ ห้าม — production บน VPS ยังเป็น RandomForest 13 features เดิม, `ml_enforcement_enabled` = `false`; **ห้ามแก้ไขอะไรบน VPS** (เข้าได้แบบอ่านอย่างเดียว) |
| Commit | ❌ ยังไม่ได้ commit |

### งานที่ทำในรอบนี้
- [x] **ดึงข้อมูลจาก VPS แบบอ่านอย่างเดียว** — `scripts/extract_vps_audit_dataset.py` อ่าน `audit.json`, `.1.gz`, `.2.gz` ผ่าน SSH ส่งผลกลับทาง stdout (ไม่เขียนไฟล์บน VPS): attack (payload rule 930-944, GET เท่านั้น) 1,149 แถว, benign (ไม่โดน rule ใดเลย + 2xx/3xx + GET + host ของ lab + signature filter) 77,632 แถว → `ml/dataset/vps_audit_labelled.jsonl` + `.stats.json`. audit log ไม่มี request body (ไม่ได้เปิด part C) — การเก็บ body ต้องแก้ config บน production ซึ่งเจ้าของโปรเจกต์ต้องตัดสินใจเอง
- [x] **Public dataset (ของจริง, license ชัดเจน)** — `ml/prepare_external_datasets.py` → `ml/dataset/external/` (อยู่ใน `.gitignore`), hash และสถิติใน `prepare_stats.json`:
  - open-appsec WAF Comparison (Apache-2.0): legitimate = browsing จริง 185 เว็บ (1.04M request), malicious = 73,924 payload (wrapper `/?p=`)
  - SR-BH 2020 (CC0, Harvard Dataverse): honeypot จริง 907k request, label ตรวจด้วยมือ; ใช้เฉพาะคลาสที่มี payload, ตัด protocol/scan/brute-force 73,595 แถว
  - เก็บไม่เกิน 3 แถวต่อกลุ่ม near-duplicate; open-appsec legit สุ่มทั้งกลุ่ม 20%, SR-BH attack 40% (RAM 7 GB)
- [x] **ตัวเทรน** (`ml/train_gen3_full_real_benchmark.py`): headline gate คำนวณบน `CORE_SOURCES` (CSIC + VPS) เพื่อให้เทียบกับรอบก่อนได้, source ภายนอกรายงานแยก; build cache (`ml/dataset/.build_cache/`); แก้ `n_jobs` เป็น physical core (เร็วขึ้น 8 เท่า); แก้ `np.isin` บน string ที่ช้ามาก (3 นาที/ครั้ง → 0.1 วินาที)
- [x] **Hybrid model** (`ml/hybrid_model.py`): token model (hashed unigram+bigram → TF-IDF → logistic regression) stacked ใต้ LightGBM (36 features + token score แบบ out-of-fold)
- [x] **เครื่องมือตรวจ**: `check_overfitting.py`, `test_comprehensive.py` รองรับ hybrid; ใหม่ `ml/evaluate_leave_source_out.py` (LOSO), `ml/experiment_content_model.py`

### ผลลัพธ์เทียบกัน (holdout CORE, ถ่วงน้ำหนักตามรูปแบบ)
| Model | Benign | Attack | หมายเหตุ |
| :--- | :---: | :---: | :--- |
| LightGBM 36 features (ข้อมูลเดิม) | 98.01% | 65.41% | candidate รอบก่อน `20260927-165254` |
| LightGBM 36 features (ข้อมูลใหม่) | 98.50% | 65.28% | ROC-AUC ขึ้นจาก 0.876 → 0.932 แต่ recall ที่จุดตัดไม่ขยับ |
| **Hybrid (token + LightGBM)** | **98.58%** | **91.04%** | CSIC attack 90.9%, ModSec VPS 91.8%, SR-BH 99.3%, benign ของ VPS 100%; latency p50 2.5 ms |

### ⚠️ ทำไมยังไม่ควร promote hybrid
1. **Payload ผูกกับบริบทของ dataset:** `POST / p=;cat /etc/shadow` → 1.00 แต่ `POST /api/run cmd=;cat /etc/shadow` → 0.002 และ `cmd=|whoami` → 0.000 — command injection ส่วนใหญ่ในข้อมูลมาจาก wrapper `/?p=` ของ open-appsec ส่วน token อย่าง `api`/`run` ถูกเรียนรู้ว่าเป็น benign
2. **ชุด 63 scenario:** normal 37/37 แต่ attack แค่ **18/26** (แย่กว่า LightGBM 36 features เดิมที่ได้ 23/26)
3. **Leave-one-source-out ต่ำทุกแบบ:** เมื่อไม่เคยเห็น source นั้น — CSIC attack 13%, SR-BH 12%, ModSec VPS 6%, benign เว็บจริง open-appsec แค่ 40% → โมเดลยังเรียนรู้ลักษณะของแต่ละ dataset มากกว่าลักษณะของการโจมตี
4. check_overfitting: attack recall train 99.05% vs holdout 91.04% (ห่าง 8%)

### งานที่ค้างอยู่ (ทำต่อตามลำดับ)
1. **แก้บั๊กใน `request_units()` (`ml/hybrid_model.py`)** — ส่ง `max_num_fields=MAX_UNITS` ให้ `parse_qsl` ทำให้ `ValueError: Max number of fields exceeded` เมื่อ body มี field > 64 → ต้องตัดเองแทน (parse ไม่จำกัดแล้ว slice) — การทดลอง `ml/experiment_unit_model.py` จึง **crash ตอนสร้าง dataset ยังไม่มีผล**
2. **รัน `ml/experiment_unit_model.py`** — โมเดลให้คะแนนราย unit (path segment / ชื่อ-ค่า param / JSON leaf) แบบ multiple-instance learning แล้วเอาค่าสูงสุด (`UnitTokenModel`, `Gen3UnitModel` ใน `ml/hybrid_model.py`) เพื่อตัดบริบทออกโดยโครงสร้าง; เทียบ A / U / CU / hybrid ด้วย **context-transfer stress test** (payload จริงจาก holdout ใส่ใน request benign จริงจาก holdout — ใช้ประเมินเท่านั้น), 63 scenario และ LOSO
3. เลือกตัวที่ผ่านทั้ง gate และ robustness tests แล้วทำให้เป็น pipeline หลักในตัวเทรน
4. ต้องขอการตัดสินใจจากเจ้าของโปรเจกต์: (ก) จะเพิ่ม data augmentation (ย้าย payload จริงไปอยู่ในบริบทอื่น) หรือไม่ — roadmap ปัจจุบันห้าม synthetic rows; (ข) นิยาม gate สำหรับ CSIC; (ค) เปิด ModSecurity audit part C บน VPS เพื่อเก็บ body หรือไม่ (ต้องทำเอง และขัดกับกฎห้ามเก็บ raw body)

### วิธีกลับมาทำต่อ
```bash
# ใน WSL: cd /home/chirachot/seminar/waf_project  (ข้อมูล external อยู่ใน ml/dataset/external/ แล้ว ไม่ต้องโหลดใหม่)
PYTHONPATH=. .venv/bin/python ml/experiment_unit_model.py          # หลังแก้บั๊กข้อ 1 (สร้าง dataset ใหม่ ~6 นาที)
PYTHONPATH=. .venv/bin/python ml/train_gen3_full_real_benchmark.py # hybrid candidate (~10 นาทีเมื่อมี cache)
PYTHONPATH=. .venv/bin/python ml/evaluate_leave_source_out.py      # LOSO ของ candidate ล่าสุด (~15 นาที)
PYTHONPATH=. .venv/bin/python ml/test_comprehensive.py             # 63 scenario
# ถ้าต้องโหลด public dataset ใหม่: ดู URL/sha256 ใน ml/prepare_external_datasets.py และ ml/dataset/external/prepare_stats.json
```

### เรื่องความปลอดภัยที่พบ (นอก ML)
- ใน `audit.json.2.gz` บน VPS มี subdomain เลียนแบบธนาคาร/บริการใต้ domain ของโปรเจกต์ เช่น `bsberbank.8721sbermegamarket.ld48stp821tyfk3q.waf-it-kku.online`, `0www.blablacar.ld48stp821tyfk3q.waf-it-kku.online` — อาจมีการใช้ wildcard DNS ทำ phishing; ควรตรวจ DNS/tenant (ไม่ได้นำข้อมูลจาก host เหล่านี้มาใช้)
- `waf-nginx` บน VPS กลับมาทำงานปกติแล้ว (healthy, ตรวจเมื่อ 27/09 ~20:00)

---

## 📍 จุดที่พักงานรอบก่อน (27/09/2026 16:56) — เก็บไว้เป็นประวัติ

### สถานะโดยย่อ
| หัวข้อ | สถานะ |
| :--- | :--- |
| Pipeline เทรน/ประเมิน ตรงตาม `WAF_GEN3_ROADMAP.md` 3.1-D..G | ✅ เสร็จ (local) |
| Candidate ล่าสุด | `ml/models/archive/task3-1-real-augmented-candidate-20260927-165254/` (มี `experiment_report.json`, `dataset_manifest.json`, `train_script_snapshot.py`) |
| ผล Unseen holdout (1 รูปแบบ request = 1 หน่วย) | Benign **98.01%** / Attack **65.41%** — ❌ ไม่ผ่าน gate (98.5% / 85%) |
| Promotion / ขึ้น VPS | ❌ ห้าม — เป็น experiment เท่านั้น; production บน VPS ยังเป็น RandomForest 13 features เดิม, `ml_enforcement_enabled` ยัง `false` |
| Commit | ❌ ยังไม่ได้ commit อะไรเลย |

### งานที่ทำเสร็จในรอบนี้
- [x] `/code-review` โฟลเดอร์ `ml/` — แก้ 3 บั๊ก: `/predict` และ ONNX export/inference ล็อก 13 คอลัมน์ (จะพังเมื่อ retrain ด้วย 36 features) → ใช้ `feature_columns_for_model()`; `/capture` ไม่ fail-open จริง → ครอบ try/except
- [x] ตรวจซ้ำผล 98.72% / 85.47% → พบว่าละเมิด 3.1-D/E/F (ดู Correction ด้านล่าง และ `WAF_GEN3_ROADMAP.md` ข้อ 2.3)
- [x] แก้ label: ModSec ใช้เฉพาะ payload rule 930-944 (ตัด protocol-only 6,590 แถว + non-GET ไม่มี body 46 แถว), telemetry ใช้เฉพาะ benign, ตัด URL เขียนเอง 69 แถว
- [x] แก้การประเมิน: near-duplicate group (ไม่รวม method) + ถ่วงน้ำหนัก 1/ขนาดกลุ่ม, split/CV แบบ group-level stratified ตาม label × source, hyperparameter (grid 12 config) และ threshold เลือกจาก dev out-of-fold เท่านั้น, holdout ประเมินครั้งเดียว
- [x] แก้ feature: เพิ่ม `RESTRICTED_FILE_PATTERN` (CRS 930130: `.env`, `.git`, `.aws` ฯลฯ) → ModSec payload attack recall 77% → 94%
- [x] `check_overfitting.py` / `test_comprehensive.py` ใช้ split/น้ำหนัก/threshold ชุดเดียวกับตัวเทรน
- [x] Unit tests 25/25 ผ่าน, ชุดทดสอบ 63 scenario ผ่าน 59/63 (normal 36/37, attack 23/26)

### ไฟล์ที่แก้ในรอบนี้ (ยังไม่ commit)
- `ml/train_gen3_full_real_benchmark.py` (เขียนใหม่เกือบทั้งไฟล์), `ml/check_overfitting.py`, `ml/test_comprehensive.py`
- `ml/feature_engineering.py` (`feature_columns_for_model`, `RESTRICTED_FILE_PATTERN`), `ml/test_feature_engineering.py` (+2 tests)
- `ml/ml_api.py`, `ml/onnx_export.py`, `ml/onnx_inference.py` (จาก code review)
- เอกสาร: `WAF_GEN3_ROADMAP.md`, `PROGRESS_GEN3_CHECKPOINT.md`, `ML_LIGHTGBM_END_TO_END_SUMMARY.md`
- สำเนาสคริปต์เดิมเก็บไว้ที่ `ml/models/archive/task3-1-real-augmented-candidate-20260925-124804/*_snapshot.py`
- หมายเหตุ: `ml/feature_engineering.py`, `ml/ml_api.py` มี uncommitted changes เดิมของเจ้าของโปรเจกต์ปนอยู่ก่อนแล้ว — ตรวจ diff ก่อน commit

### เพดานที่เหลือ (ทำไมยังไม่ผ่าน)
- Attack ที่มีสัญญาณโจมตีใน request (70% ของรูปแบบ) จับได้ **84.15%**; CSIC parameter tampering ที่ไม่มีสัญญาณเลย (30%) จับได้ **21.04%** — แยกจาก benign ไม่ได้ถ้าไม่รู้ spec ของแอป และห้ามทิ้ง/relabel (ข้อ 2.1)
- Benign จริงจาก VPS มีแค่ ~371 รูปแบบ (26,000+ แถวเป็น request ซ้ำ)
- ทุก config ใน grid ห่างกัน < 1.5pp → ปรับโมเดลต่อไม่ช่วย ต้องแก้ที่ข้อมูล

### งานถัดไป (รอการตัดสินใจ)
1. **3.1-B เก็บ benign จริงให้หลากหลาย** จาก VPS/แอปอื่น (ตอนนี้ ~371 รูปแบบ)
2. **แก้ `scripts/extract_modsec_attacks.py` ให้เก็บ request body** เพื่อให้ SQLi/XSS แบบ POST ใช้เทรนได้ (ตอนนี้ payload attack จริงเกือบทั้งหมดเป็น LFI)
3. **ตัดสินใจเรื่องนิยาม gate:** จะรายงาน CSIC structural-only แยกจาก gate หลักหรือไม่ — ต้องอนุมัติก่อน ห้ามเปลี่ยนเอง
4. จากนั้นจึงค่อยทำ Phase 3.2 (ONNX export ของ LightGBM ต้องใช้ `onnxmltools`) และ Shadow Mode บน VPS

### วิธีกลับมาทำต่อ
```bash
# ใน WSL: cd /home/chirachot/seminar/waf_project
PYTHONPATH=. .venv/bin/python ml/train_gen3_full_real_benchmark.py   # เทรน + grid + holdout (~8 นาที)
PYTHONPATH=. .venv/bin/python ml/check_overfitting.py                # ใช้ split/threshold เดียวกัน
PYTHONPATH=. .venv/bin/python ml/test_comprehensive.py               # 63 scenario
PYTHONPATH=. .venv/bin/python -m pytest ml/tests ml/test_feature_engineering.py -q
```

### เรื่องค้างนอก ML (พบระหว่างรอบนี้)
- **VPS `waf-nginx` crash-loop** (พบ 27/09 ~15:50 ICT): บล็อก `location @deception` ที่ยังไม่ commit ใน `nginx/templates/conf.d/default.conf.template` (5 จุด) ใช้ `proxy_pass` ที่มี URI ใน named location → nginx ไม่ start. เจ้าของโปรเจกต์รับไปแก้เอง — ตรวจสถานะอีกครั้งก่อนเริ่มงานรอบหน้า

---

> [!WARNING]
> **Correction (27/09/2026):** ตัวเลขในเอกสารนี้ reproduce ได้ตรงจริง แต่ใช้เป็นหลักฐาน promotion ไม่ได้ เพราะ pipeline ขัดกับ `WAF_GEN3_ROADMAP.md` ข้อ 3.1-D/E/F:
> - ข้อมูล ModSecurity 6,590 จาก 7,513 แถวเป็น protocol-only event (6,344 แถวคือ Juice Shop `/socket.io/` ที่ CRS บล็อกผิดด้วย rule 920420) แต่ถูกติด label เป็น attack
> - "Representative Benign Web Traffic" 69 แถว (หัวข้อ 3 ข้อ 5) เขียนขึ้นในโค้ด ไม่ใช่ traffic จริง และซ้ำกับ scenario ที่ใช้ทดสอบในหัวข้อ 2
> - Split แบบสุ่มทำให้ near-duplicate ข้ามฝั่ง train/holdout ได้; "Optimal Threshold 0.7085" จูนบน holdout เอง; latency 4.97 µs เป็นค่าเฉลี่ย batch (ต่อ 1 request จริง ≈ 1.9 ms)
>
> **ผลหลังแก้ pipeline** (`ml/models/archive/task3-1-real-augmented-candidate-20260927-165254/`): นับแบบ "1 รูปแบบ request = 1 หน่วย" (benign 3,357 / attack 6,537 รูปแบบ), group-level split, hyperparameter และ threshold เลือกจาก out-of-fold เท่านั้น → Unseen holdout **Benign 98.01% / Attack 65.41%** (ModSec payload attack 94.15%; attack ที่มีสัญญาณโจมตี 84.15%; CSIC parameter tampering ที่ไม่มีสัญญาณ 21.04%), latency ต่อ request ≈ 1.8 ms — **ไม่ผ่าน promotion gate** เพดานมาจากข้อมูล รายละเอียดดู `WAF_GEN3_ROADMAP.md` ข้อ 2.3
>
> เนื้อหาด้านล่างเก็บไว้เป็นประวัติเท่านั้น

---

## 1. ผลลัพธ์ของโมเดลล่าสุด (Latest Model Benchmark)

* **โมเดลที่บันทึก:** [`ml/models/archive/task3-1-real-augmented-candidate-20260925-124804/lightgbm_waf_model.joblib`](ml/models/archive/task3-1-real-augmented-candidate-20260925-124804/lightgbm_waf_model.joblib)
* **รายงานผลอย่างเป็นทางการ:** [`ml/models/archive/task3-1-real-augmented-candidate-20260925-124804/experiment_report.json`](ml/models/archive/task3-1-real-augmented-candidate-20260925-124804/experiment_report.json)

### ตัวชี้วัดบน Unseen Holdout Test Set (9,767 ตัวอย่างจริง ไม่มีการ Leak)
| เมตริก (Metric) | เกณฑ์เป้าหมาย | ผลลัพธ์ (Default Mean Threshold = 0.7442) | ผลลัพธ์ (Optimal Threshold = 0.7085) | สถานะ |
| :--- | :---: | :---: | :---: | :---: |
| **Benign Recall** | ≥ 98.50% | **98.72%** (FP=66) | **98.51%** (FP=77) | ✅ **PASSED SAFETY GATE** |
| **Attack Recall** | ≥ 85.00% | **85.47%** (FN=668) | **86.65%** (FN=614) | ✅ **PASSED ACCURACY GATE** |
| **ROC-AUC** | ≥ 0.9500 | **0.9885** | **0.9885** | ✅ **NEAR-PERFECT SEPARATION** |
| **Inference Latency** | < 50 µs | **4.97 µs** (0.004 ms) | **4.97 µs** | ✅ **ULTRA FAST (LIGHTGBM)** |
| **ความถูกต้องรวม (Accuracy)**| - | **92.48%** | **92.90%** | ✅ |

---

## 2. การเปรียบเทียบผลทดสอบ Traffic จริง (Before vs After)

ทดสอบกับชุดทดสอบ 63 Scenarios ครอบคลุมการใช้งานเว็บจริงและการโจมตีทุกมิติ:

| หมวดหมู่การทดสอบ | ก่อนดึง Nginx Benign | หลังดึง Nginx Benign (Pure ML) | หลังรวม Clean Guardrail (Hybrid) | การเปลี่ยนแปลง |
| :--- | :---: | :---: | :---: | :---: |
| **Normal Traffic ปล่อยผ่าน (ALLOW)** | 10/37 (27.0%) | **31/37 (83.8%)** | **37/37 (100.0%)** | 🟢 **ก้าวกระโดด +56.8% ถึง +73.0%** |
| **Attack Traffic สกัดกั้น (BLOCK)** | 25/26 (96.2%) | **25/26 (96.2%)** | **21/26 (80.8%)** | 🔴 **รักษาความแม่นยำ 96.2% ไว้อย่างเด็ดขาด** |
| **คะแนนรวม (Overall Score)** | 35/63 (55.6%) | **56/63 (88.9%)** | **58/63 (92.1%)** | 🎯 **ผ่านเกณฑ์เกิน 88-92%** |

### เจาะลึกจุดที่ปลดล็อกสำเร็จ (Breakthrough Highlights)
1. **Static Assets (CSS, JS, PNG, JPG, Favicon, Fonts):**
   - *เดิม:* โดนบล็อก 100% (P(Attack) > 85%) เพราะเป็น URL สั้นไม่มี Parameter
   - *ตอนนี้:* **ผ่าน 100%** ทุกตัว P(Attack) ลดเหลือเพียง **0.54% – 0.84%**
2. **หน้าเว็บแรกและหน้าหลัก (`/`, `/index.html`, `/about.html`):**
   - *เดิม:* `/index.html` โดนบล็อก P(Attack) = 89.98%
   - *ตอนนี้:* **ผ่านฉลุย P(Attack) = 6.49%**
3. **การค้นหาและฟิลเตอร์ (`q=mechanical+keyboard`):**
   - *เดิม:* โดนบล็อก P(Attack) = 91.08% เพราะนับเครื่องหมาย `+` เป็นอักขระโจมตี
   - *ตอนนี้:* แก้ไขให้รู้ว่า `+` ใน URL คือ space encoding ส่งผลให้ **P(Attack) ลดเหลือ 3.81% (ALLOW)**
4. **ภาษาไทยและ Unicode (`/search?q=การเรียน`):**
   - *เดิม:* โดนบล็อก P(Attack) = 99.84% เพราะมอง percent-encoding UTF-8 เป็นการหลบหลีก (Obfuscation)
   - *ตอนนี้:* แยกแยะ ASCII Encoding ออกจาก UTF-8 Multi-byte ส่งผลให้ **P(Attack) ลดเหลือ 1.42% (ALLOW)**
5. **ฟอร์มผู้ใช้งานทั่วไป (Login, Register, Checkout, Feedback):**
   - **ผ่าน 100% ทุกประเภทฟอร์ม** (P(Attack) อยู่ระหว่าง 5% – 29%)

---

## 3. ข้อมูลที่ใช้เทรน (Data Provenance — 100% Real, Zero Synthetic)

ชุดข้อมูลเพิ่มขึ้นเป็น **48,832 Unique Rows** (คลีนจาก 92,655 แถว):
1. **CSIC 2010 Cleaned:** 25,094 แถว (Benchmark มาตรฐาน)
2. **VPS Live Telemetry Benign:** 17,371 แถว (ทราฟฟิกจริงบน VPS)
3. **VPS Nginx Clean Access Log:** 9,381 แถว (ดึงจาก `/root/waf_project/logs/nginx/access.json` เฉพาะ HTTP 200/304 ที่ผ่านการกรอง)
4. **VPS ModSecurity Blocked Attacks:** 7,513 แถว (OWASP CRS Audit Logs จริง)
5. **Representative Benign Web Traffic:** 69 แถว (URL มาตรฐานของ Web Application ทั่วไป)

---

## 4. โครงสร้างฟีเจอร์ (36 Universal Features)

- ปรับแต่ง `ENCODED_BYTE_PATTERN` ให้จับเฉพาะ ASCII hex (`%[0-7][0-9a-fA-F]`) เพื่อไม่ให้ลงโทษภาษาไทย/Unicode
- นำเครื่องหมาย `+` ออกจาก `punct_chars` ในการคำนวณ Parameter Tampering เพราะเป็นเครื่องหมายเว้นวรรคมาตรฐานของ URL
- ตั้งค่า `url_path_entropy = 0.0` อัตโนมัติเมื่อเป็น `is_static_asset == 1` เพื่อไม่ให้ไฟล์ CSS/JS/Image ที่มีชื่อสั้นโดนเข้าใจผิดว่าเป็น Scanner Probe
- ทุกฟีเจอร์ผ่าน Unit Tests ครบถ้วน **23/23 tests passed**

---

## 5. แผนการถัดไป (Next Steps)

1. **Phase 3.2 — ONNX Runtime Export:**
   - ทำสคริปต์ Export โมเดล 36 Features ตัวใหม่นี้เป็น `.onnx`
   - ทดสอบความเร็วเทียบกับ Baseline Random Forest
2. **Phase 3.3 — Shadow Mode Live Verification บน VPS:**
   - นำไปวางขนานกับ ModSecurity เพื่อทดสอบ Audit Log ในการใช้งานจริง 24-48 ชั่วโมง
