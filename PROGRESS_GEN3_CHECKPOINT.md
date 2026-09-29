# WAF Gen 3 Development Checkpoint & Progress Status
**Date:** 2026-09-28 (16:45 ICT) — พักงานรอบที่ 3 (เดิม 2026-09-27 21:11)  
**Branch:** `trainmodelgen3`  
**Status:** ⏸️ **Value features (detector ระดับค่า) ช่วยได้จริง; ฟีเจอร์บริบทคือต้นเหตุที่โมเดลไม่ทนต่อ source ใหม่ — รอรันแบบ E + ablation บน Colab**

---

## 📍 จุดที่พักงานล่าสุด (28/09/2026 16:45)

### สิ่งที่ทำในรอบนี้
- [x] **Colab (ฟรี)**: `ml/waf_gen3_colab.ipynb` — venv Python 3.12, dataset/cache/ผลเก็บใน `MyDrive/waf_ml/`, log ขึ้น Drive ทุก 2 นาที (`live_logs/`), ผลแบบไม่บีบอัดใน `results/<stamp>/`; เครื่อง local (WSL RAM 3 GB) สร้าง dataset เต็มไม่ได้
- [x] **แก้บั๊ก `request_units()`** (`parse_qsl(max_num_fields)` raise) — ปลดล็อก `experiment_unit_model.py`
- [x] **`ml/value_features.py`** — 17 ฟีเจอร์ระดับ unit (path segment / param / JSON leaf) รวมด้วย max/count: libinjection SQLi/XSS + command injection, traversal, sensitive file, SSTI/JNDI, NoSQL, SSRF, code exec, XXE, CRLF หลัง decode URL/HTML/`\x`/`%u` + overlong UTF-8
  - ตรวจกับข้อมูลจริง: จับผิด traffic เว็บจริง (open-appsec legitimate 271k) **0.52%**; จับ payload open-appsec: cmdexe 97.5%, traversal 78.6%, XSS 89%, Log4Shell/XXE 100%
  - บั๊กความปลอดภัยที่เจอและแก้: `%uD800` (lone surrogate) ทำให้ libinjection crash → request เดียวทำให้ scoring พังได้
- [x] **`ml/experiment_value_features.py`** — เทียบ config ด้วย 4 เกณฑ์: CORE gate, context-transfer stress test, 63 scenario, leave-one-source-out
- [x] **SR-BH label noise**: คลาส "000 - Normal" มีการโจมตีจริง (shellshock, `;cat /etc/passwd`, `<script>alert(1)`) — ตัดสินใจโดยเจ้าของโปรเจกต์ (ทางเลือกที่ 1): แถว Normal ที่ detector จับได้ → **ตัดออก (unknown) ไม่ relabel** ทั้ง train และ eval → ตัด 25,526 จาก 65,110 แถว (39% ของรูปแบบที่ไม่ซ้ำ; ในไฟล์ดิบ ~8%) — บันทึกใน `data_integrity.exclusions.srbh_benign_contradicted_by_detectors`
- [x] `prepare_external_datasets.py`: Harvard Dataverse ตอบ 403 กับ User-Agent ของ urllib → ใส่ User-Agent

### ผล (Colab, public data เท่านั้น: CSIC + open-appsec + SR-BH, ไม่มีข้อมูล VPS → CORE = CSIC อย่างเดียว เทียบกับ candidate 91.04% ไม่ได้)
ผลเต็ม: `MyDrive/waf_ml/results/`, archive `experiment-value-features-20260928-092136` (โมเดลอยู่ใน Drive `models/`)

| Config | CSIC benign / attack | Holdout ทุก source attack | Stress (payload ในบริบทใหม่) | 63 scenario attack | LOSO attack เฉลี่ย |
| :--- | :---: | :---: | :---: | :---: | :---: |
| A 36 ฟีเจอร์เดิม | 97.82 / 59.88 | 93.70 | 27.9% | 20/26 | 22.7% |
| B + value features | **98.16 / 60.94** | **95.54** | 43.8% | **23/26** | 35.2% |
| C B + monotone | 97.91 / 59.44 | 94.88 | 37.9% | 21/26 | 30.3% |
| D C − ฟีเจอร์บริบท 6 ตัว | 97.82 / 53.02 | 92.55 | **66.1%** (FP 0.2%) | 21/26 | **57.2%** |

- **B ดีกว่า A ทุกตัว** (SQLi holdout 91.3 → 95.6%, RCE 97.1 → 100%) — `v_detector_units` เป็นฟีเจอร์อันดับ 1 (gain ~15 เท่าของอันดับ 2)
- **ฟีเจอร์บริบท** (`url_path_entropy`, `query_body_entropy`, `avg/max_param_length`, `path_depth`, `param_count`) ทำให้โมเดล "อธิบาย payload ทิ้ง" เมื่อ request ดูเหมือน traffic ปกติ: ตัดออก (D) → stress 27.9 → 66.1%, SR-BH ที่ไม่เคยเห็น 1.3 → 66.7%; แลกกับ CSIC −7pp และ **LFI holdout 99.9 → 91.3%**
- **Monotone แย่ลงทุกครั้ง** (C < B, และ C/D หลุด NoSQL + Log4Shell ใน scenario)
- เพดานเดิม: CSIC ที่ไม่มีสัญญาณโจมตี 11–20% ทุก config (gate CSIC ≥ 85% ทำไม่ได้ด้วยฟีเจอร์); admin-path probe (`/wp-admin`, `/phpmyadmin`, `/actuator`) หลุดทุก config — เหมาะเป็นกฎราย tenant ไม่ใช่ detector; traffic เว็บจริงที่ไม่เคยเห็นยังผ่านแค่ 37–61%
- ข้อควรระวัง: benign ของ SR-BH ใน LOSO สูงเกินจริงเล็กน้อย เพราะแถวที่ตัดคือแถวที่ detector จับได้

### รอบที่ 2 (17:13): E + ablation และ ⚠️ Correction จาก scrutiny
Archive `experiment-value-features-20260928-101316`: E (ไม่มีบริบท, ไม่ monotone) CSIC 98.16/57.71, stress 59.1%; ใส่ฟีเจอร์บริบทกลับทีละตัว — `url_path_entropy` คืน LFI เป็น 100% แต่ SR-BH LOSO attack (threshold คงที่) 4.7%; `query_body_entropy` stress 61.3% / FP 0%, CSIC benign 98.74%

> [!WARNING]
> **Correction (28/09 17:40, จาก `/scrutinize`):** ตัวเลข "LOSO attack" ของทั้งสองรอบใช้ threshold เดียวที่เลือกจาก OOF ของโมเดลที่เทรนทุก source แล้วนำไปใช้กับโมเดลที่เทรนใหม่โดยไม่มี source นั้น → วัด **การเลื่อนของคะแนน (calibration)** ปนกับความสามารถในการแยก เช่น SR-BH เมื่อไม่เคยเห็น: B attack 4.8% / benign 99.75% / **AUC 0.911** vs E attack 76.1% / benign **91.97%** / AUC 0.890 — E ดูดีเพราะให้คะแนนสูงขึ้นทั้งสองคลาส. ดังนั้น (1) ข้อสรุปว่า `url_path_entropy` / `path_depth` เป็นลายนิ้วมือ dataset **ถอนออก** (AUC 0.897 / 0.902 ≥ E); (2) "monotone แย่ลง" สรุปจาก C vs B เท่านั้น — เมื่อตัดบริบทแล้ว D ดีกว่า E ใน stress (66.1 vs 59.1) และ benign เว็บจริงที่ไม่เคยเห็น (60.8 vs 45.9%); (3) F / E / D ต่างกันอยู่ในระดับ noise ของ split เดียว (SE: CSIC attack ±1.5pp, stress ±1.3pp). **ที่ยังยืนยันได้:** value features ดีกว่า 36 ฟีเจอร์เดิม (SR-BH LOSO AUC 0.766 → 0.911, stress 28 → 44%) และการตัดฟีเจอร์บริบทเพิ่ม stress detection (44 → 59–66%) จริง
>
> แก้ `experiment_value_features.py`: leave-one-**dataset**-out (open-appsec legit + malicious เป็นรอบเดียว) รายงาน AUC + attack recall ที่ benign 98.5% (ไม่ขึ้นกับ threshold) และ benign/attack ที่ threshold จาก dataset ที่ใช้เทรนเท่านั้น; ทำซ้ำ 3 holdout fold (mean ± std); เพิ่ม `D_plus_query_body_entropy`

**Audit แถว SR-BH ที่ตัดออก (28/09 17:50):** จาก request "000 - Normal" ที่ไม่ซ้ำ 90,951 รายการ detector จับได้ 31,944 (35.1%); สุ่ม 200 รายการ (seed 28) ตรวจด้วยตา → **200/200 เป็นการโจมตีจริง** (scanner ฉีด `;cat /etc/passwd`, `/ sleep(15) /`, `'"<script>alert(1);</script>`, shellshock `() { :;}; /bin/sleep 15`, `%';SELECT SLEEP(5)#` เข้าไปใน path segment ของ WordPress) — ขอบบนของสัดส่วน benign ที่ถูกตัดผิด ≈ 1.5% (rule of three) → การตัดตามข้อ 1 สมเหตุสมผล ความกังวลเรื่อง circularity (Major 4) ลดลงเหลือระดับเล็กน้อย

### รอบที่ 3 (18:39): 3 fold + leave-one-dataset-out (archive `experiment-value-features-20260928-113913`)
| Config | CSIC benign / attack (mean ± sd) | Stress (control FP) | Scenario attack | AUC ที่ไม่เคยเห็น: CSIC / OpenAppSec / SR-BH |
| :--- | :---: | :---: | :---: | :---: |
| A 36 เดิม | 98.6 / 58.5 ± 1.0 | 27.0 ± 0.7 (0.05%) | 19.7 | 0.700 / 0.777 / 0.727 |
| B + value | 98.5 / **60.3 ± 0.5** | 42.4 ± 1.4 (0%) | **23** | **0.714** / 0.937 / 0.907 |
| D no-context + monotone | 98.4 / 51.6 ± 1.0 | **67.6 ± 1.8** (0.36%) | 20.7 | 0.705 / 0.938 / 0.863 |
| E no-context | 98.4 / 57.0 ± 0.7 | 58.0 ± 2.1 (0.18%) | 21.3 | 0.685 / 0.944 / 0.885 |
| **F = E + query_body_entropy** | **98.7** / 56.6 ± 0.5 | 60.1 ± 1.0 (**0.09%**) | **23** | 0.705 / **0.951** / **0.925** |
| D + qbe | 98.4 / 53.2 ± 0.8 | 61.1 ± 2.8 (0.18%) | 21.7 | 0.709 / 0.941 / – |

→ **ชุดฟีเจอร์ที่เลือก: F (48 ฟีเจอร์)** — ดีกว่า B ด้าน stress (+18pp, เกิน 10 sd) และ AUC บน dataset ที่ไม่เคยเห็น แลกกับ CSIC attack −3.7pp; เมื่อมี qbe แล้ว monotone ไม่ช่วย. "attack@benign98.5" ของรอบนี้โดนบั๊ก grid (OpenAppSec = 0 ทุก config) → แก้เป็น exact quantile (`18d8a6b`) และรัน `--only-lofo` ใหม่ (ผลแรก: OpenAppSec A 9.5% → B 80.8%). ⚠️ ที่ threshold จาก dataset อื่น เว็บจริงที่ไม่เคยเห็น (open-appsec legit) ผ่านแค่ 37–66% ทุก config → ต้อง Silent → Tuning ราย tenant ก่อน enforce

### รอบที่ 4 (19:10): leave-one-dataset-out ด้วยตัววัดแบบ exact (archive `experiment-value-features-20260928-121047`)
Attack recall ที่ benign 98.5% บน dataset ที่ไม่เคยเห็น (CSIC / OpenAppSec / SR-BH): A 30.8 / 9.5 / 5.3 · B 38.7 / **80.8** / 38.8 · D 39.6 / 66.1 / 17.1 · E 24.5 / 75.9 / 22.6 · **F 41.0 / 78.0 / 64.3** · D+qbe 39.8 / 76.0 / 27.5 → F ดีที่สุดโดยรวม (แบบเดียวที่ SR-BH > 60%)

**เทียบกับ Promotion Gate v2** (`WAF_GEN3_ROADMAP.md` 3.1-G.0, อนุมัติ 28/09 — ทุก dataset น้ำหนักเท่ากัน): F **G3 = 61.1%** (เป้า ≥ 70%) → ❌ ยังไม่ผ่าน; G4 ต่ำสุด = CSIC ที่ไม่เคยเห็น 41.0% (เป้า ≥ 40%); G5 scenario 37/37 + 23/26, stress 60.1%. G1/G2 ยังไม่มีตัวเลขที่ยืนยันได้ — ต้องให้ `ml/promotion_gate.py` คำนวณจากรายงาน 3 fold (อยู่ใน Drive) ร่วมกับรายงานรอบที่ 4
> ⚠️ Correction: ตาราง "F เทียบกับ gate" ที่รายงานในแชทก่อนหน้านี้ใส่ค่า benign open-appsec ~99.8%, attack holdout ~93–95% และ CSIC signal ~79% โดยไม่ได้ดึงจากรายงานของ F จริง — ถอนออก; ใช้ผลจาก `ml/promotion_gate.py` แทน

### รอบที่ 5 (21:44): full run ด้วยโค้ดสุดท้าย + Promotion Gate v2 (archive `experiment-value-features-20260928-144424`, `live_logs/gate.log`)
ทุกตัวเลขจากรายงานเดียว (3 fold + leave-one-dataset-out, threshold แบบ exact)

| Config | G1 benign ทุก dataset | G2 known attack เฉลี่ย | G3 unseen attack เฉลี่ย | G4 ต่ำสุด | G5 | ผ่าน |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| A 36 เดิม | ✅ 98.66 | ❌ 84.0 | ❌ 15.2 | ❌ 5.3 | ❌ | 1/5 |
| B + value | ❌ 98.49 | ✅ 85.6 | ❌ 52.8 | ❌ 38.7 | ❌ (stress 42%) | 1/5 |
| D | ❌ 98.43 | ❌ 81.1 | ❌ 40.9 | ❌ 17.1 | ❌ | 0/5 |
| E | ❌ 98.41 | ❌ 83.5 | ❌ 41.0 | ❌ 22.6 | ❌ | 0/5 |
| **F = E + qbe** | ✅ **98.69** | ❌ 83.6 | ❌ **61.1** | ✅ **41.0** | ✅ (37/37, 23/26, stress 60.1%) | **3/5** |
| D + qbe | ❌ 98.41 | ❌ 82.0 | ❌ 47.7 | ❌ 27.5 | ❌ | 0/5 |

F ราย dataset — known: CSIC 56.7 / open-appsec 98.0 / SR-BH 96.2; unseen: CSIC 41.0 / open-appsec 78.0 / SR-BH 64.3. ช่องว่าง: G2 −1.4pp (CSIC ต้อง ≈ 61%), G3 −8.9pp. G1 ถูกกำหนดโดย CSIC ทุก config (threshold เลือกที่ 98.5% บน CSIC OOF พอดี จึงแกว่งรอบเกณฑ์) → รอบหน้าควรเผื่อระยะให้ threshold. **ชุดฟีเจอร์ F ถูกล็อกเป็นชุดหลัก**

## ☀️ เริ่มงานเช้า 29/09/2026 — เทรนโมเดลสำหรับใช้งานจริง (ชุด F)
เตรียมไว้แล้ว (ทดสอบบนเครื่อง local ด้วยข้อมูลจริงชุดย่อยครบทุกขั้น):
- `ml/gen3_model.py` — นิยามชุด F ที่เดียว + `Gen3FModel` (คำนวณฟีเจอร์ + ให้คะแนน), latency ~0.3 ms/request
- `ml/train_final_gen3.py` — เทรนด้วยข้อมูลทั้งหมด, threshold ให้ **benign ทุก dataset ≥ 99%** จาก OOF (เผื่อระยะจาก G1 98.5%), scenario, latency, `model_card.json`
- `ml/ml_api.py` — `POST /predict-gen3` (shadow: ให้คะแนนอย่างเดียว ไม่บล็อก), `/health` → `gen3_shadow`; โหลดเฉพาะเมื่อมีไฟล์ `ml/models/gen3/gen3_f_model.joblib` — endpoint เดิมไม่เปลี่ยน
- notebook ค่าตั้งต้นใหม่: `RUN_FINAL_MODEL = True`, `EXPERIMENT_MODE = "none"`

**ขั้นตอน:**
1. Colab → เปิด notebook จากลิงก์ (แท็บใหม่) → **Connect (CPU)** → รอ RAM/Disk ขึ้น → **Runtime → Run all** (~30–60 นาที) — ไม่ต้องแก้ค่าใดๆ
2. ผล: `MyDrive/waf_ml/models/gen3-final-f-<เวลา>/` (`gen3_f_model.onnx` + `.joblib`) + `MyDrive/waf_ml/results/<เวลา>/gen3-final-f-<เวลา>/model_card.json`
   - cell โมเดลจริงแสดง Scenario 63 ข้อ แล้วตามด้วย Precision / Recall / F1 (ของ scenario และแบบ OOF ต่อ dataset)
3. ดาวน์โหลด `gen3_f_model.onnx` ไปวางที่ `ml/models/gen3/` (ไม่ขึ้น git — `.gitignore`)
   - ให้ Claude ตรวจ model card, ทดสอบ `/predict-gen3` และ commit เฉพาะ `model_card.json`
4. (ถ้าจะแยกเครื่อง ML) ทำตาม `deploy/azure-ml/README.md` — ขั้นที่แตะ VPS ต้องได้รับอนุมัติก่อน

⚠️ **พบจากการตรวจ VPS (อ่านอย่างเดียว, 29/09):**
- venv `dashboard/backend/.venv` ถูกสร้างใหม่เมื่อ 27/09 11:58 หลังจาก `waf-ml` เริ่มทำงานไปแล้ว
- numpy, sklearn, onnxruntime และ pandas ไม่อยู่บนดิสก์แล้ว process ที่รันอยู่ยังใช้ไฟล์ที่ถูกลบไปแล้ว
- ถ้า restart หรือ reboot `waf-ml` จะโหลดโมเดลไม่ขึ้น (ไม่ได้แก้อะไรบน VPS)
- สถานะ: **ไม่ผ่าน promotion gate (3/5)** → ใช้เดโม / shadow เท่านั้น ห้าม enforce

### ผลโมเดลจริง (Colab 29/09 03:53 UTC, archive `gen3-final-f-20260929-035343`, public data เท่านั้น)
- threshold 0.8035 (กำหนดโดย benign 99% ของ CSIC)
- ONNX parity 6.2e-7, latency p50 0.44 ms (ONNX)
- Scenario: normal ผ่าน 37/37, attack บล็อก 23/26
  - พลาด: WordPress admin, phpMyAdmin, Spring actuator probe (คะแนน 0.0772 เท่ากับ Homepage)
  - Precision 100% / Recall 88.46% / F1 93.88%
- Out-of-fold (attack = positive, group-weighted):

| Dataset | Precision | Recall | F1 | Benign ผ่าน |
|---|---|---|---|---|
| รวม | 99.83% | 93.58% | 96.60% | – |
| OpenAppSec | 99.87% | 96.52% | 98.17% | 99.95% |
| SR-BH 2020 | 99.85% | 96.18% | 97.98% | 99.79% |
| CSIC 2010 | 99.08% | 55.95% | 71.51% | 99.01% |

- G2-style (ค่าเฉลี่ย known attack) = 82.88% ต่ำกว่าเกณฑ์ 85% → ยังไม่ promote

### ทำไม CSIC recall ต่ำ (วิเคราะห์ 29/09, อ่านอย่างเดียว, เทรน CSIC อย่างเดียว 5-fold OOF)
- **ไม่ใช่ threshold:** threshold มาจาก benign ของ CSIC เอง (binding)
- **ไม่ใช่การเทรนรวม:** เทรน CSIC อย่างเดียวได้ 60.5% เทียบกับเทรนรวม 56.0%
- **ไม่ใช่ฟีเจอร์ที่ตัดออก:** F + 5 context features ได้ 59.4%, ชุด A (36 ฟีเจอร์) ได้ 59.0%
- **สาเหตุจริง:** attack ของ CSIC ที่มี detector hit มีแค่ 23.3% แต่กลุ่มนั้นจับได้ 99.8%
  - ประเภทที่มี payload โจมตีจริงได้ recall 93.9% และ probe ไฟล์ได้ 100%
  - ~60% ของ attack เป็น parameter tampering (`loginA=`, `cantidadA=`, `dni=75B1383B04H`) ที่ผิดเฉพาะกับ schema ของแอป `tienda1` ได้ recall ~37%
  - ต้องใช้ positive model ต่อ endpoint ไม่ใช่โมเดลแบบทั่วไป

### 🔧 Canonical request form (29/09 บ่าย) — รอเทรนบน Colab
ที่มา: ทดสอบด้วย GoTestWAF/sqlmap/Nuclei (`ml/security_test/RESULTS_20260929.md`)
- SQLi เดียวกัน: form 0.993 / JSON 0.215 / multipart 0.339 / Base64 0.001
  - JSON/multipart: libinjection จับได้ แต่อักขระโครงสร้าง `{"":""}` ทำให้ฟีเจอร์โครงสร้างดูเหมือน benign
    (ใน training JSON ส่วนใหญ่เป็น benign = ลายนิ้วมือ dataset)
  - Base64: detector มองไม่เห็นเลย
- False positive 18/141 ของ GoTestWAF: ไม่มี detector จับเลย คะแนนมาจาก entropy + `%20` ที่นับเป็น encoded byte
  (ข้อความภาษาธรรมชาติในฟอร์มแทบไม่มีใน benign training data)
- แก้: `ml/canonical.py` ใช้ทั้งตอนเทรน (builder) และตอนใช้งาน (`request_features`)
  1. query/form: decode 1 ชั้น แล้ว escape เฉพาะตัวคั่น (`%2527` ยังอยู่, `%20` → `+`)
  2. JSON/multipart → form `k=v` (ไฟล์ binary ตัดทิ้ง เก็บชื่อฟิลด์)
  3. Base64 → decode เฉพาะเมื่อผลลัพธ์ทำให้ detector ทำงาน (JWT/token ไม่ถูกแตะ)
- `FEATURE_SET_VERSION = gen3-F-2026-09-29-canon` → โมเดลเก่า (raw) ถูกปฏิเสธโดยโค้ดใหม่
- promotion gate รวมเฉพาะรายงานที่ `feature_extraction` ตรงกัน (ไม่ปน raw กับ canonical)
- ผลเบื้องต้น (โมเดลเก่า + ฟีเจอร์ใหม่ = ดูทิศทางเท่านั้น): JSON/multipart 0.993, Base64 0.982; FP 18 → 3
- **ขั้นต่อไป:** Colab Run all (`EXPERIMENT_MODE="full"`, config F) → gate ของ F-canonical + โมเดลใหม่
  → รัน GoTestWAF/sqlmap/Nuclei ซ้ำ → เทียบก่อน/หลังในคู่มือ

### 📋 Plan ที่ตกลงไว้ — ยังไม่ทำ (ทำใน repo ก่อน, ขึ้น VPS ต้องได้รับอนุมัติ)
1. **ModSecurity custom rule: รายชื่อ path สแกนเนอร์ แยกตาม origin**
   - path เช่น `/wp-admin`, `/wp-login.php`, `/xmlrpc.php`, `/phpmyadmin`, `/pma`, `/actuator`, `/server-status`, `/cgi-bin/`
   - บล็อกเฉพาะ origin ที่ไม่ได้ใช้เทคโนโลยีนั้น (ตัวเลือกต่อ origin, ต่อจากแท็บ WAF Rules)
   - ไม่แก้โมเดล
2. **Shield / rate limit: 404 ถี่ต่อ IP** (nginx `auth_request /internal-shield-check` + backend + Redis)
   - เช่น 404 เกิน N ครั้งต่อนาที → challenge หรือ block IP ชั่วคราว
   - ไม่ทำใน ModSecurity เพราะ collection ต่อ IP ใน v3 รองรับจำกัด
3. **รายงานผล 2 ระดับ:** "ML อย่างเดียว" (scenario 23/26) และ "WAF ทั้งระบบ" (ยิงทดสอบผ่าน nginx จริง)
4. (ภายหลัง) positive model ต่อ endpoint เพื่อจับ parameter tampering แบบ CSIC ต้องใช้ traffic จริงของแต่ละ origin
5. (รอตัดสินใจ) รายงาน CSIC แยก "มีสัญญาณโจมตี" กับ "parameter tampering" — ถ้าจะเปลี่ยนเกณฑ์ G2 ต้องได้รับอนุมัติก่อน

### งานถัดไป (เดิม — ทำแล้ว)
1. ~~**รัน Colab โหมด `EXPERIMENT_MODE = "full"`**~~ (รอบที่ 5) (ค่าตั้งต้น, ~1 ชม.) — ได้ G1–G5 ของทุก config จากรายงานเดียวที่ใช้โค้ดสุดท้ายทั้งหมด (threshold แบบ exact ทั้ง holdout และ LOFO). โหมด `"gate"` ใช้ไม่ได้ในรอบนี้เพราะ Drive มีแต่ LOFO แบบ grid (รายงานรอบที่ 4 ไม่ถูกคัดลอกลง Drive เพราะ cell สรุปเดิม error ก่อนถึง cell zip)
2. ใช้ชุด F เป็นชุดฟีเจอร์หลักของตัวเทรน + รายงาน gate v2 แล้วรวมกับ unit (MIL) model เพื่อปิดช่องว่าง G3 (61 → 70%)
2. จากนั้นรวม config ที่ดีที่สุดกับ unit (MIL) model (`RUN_TRAINER` + `RUN_UNIT_EXPERIMENT`)
3. รอการตัดสินใจ: นิยาม gate สำหรับ CSIC structural-only; จะใช้ข้อมูล VPS บน Drive หรือไม่ (CORE gate จริงต้องใช้)

---

## 📍 จุดที่พักงานรอบก่อน (27/09/2026 21:11) — เก็บไว้เป็นประวัติ

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
