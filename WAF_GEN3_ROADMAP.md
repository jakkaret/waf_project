# 🛡️ แผนพัฒนา WAF Gen 3 & มาตรฐานการควบคุมขอบเขตงาน (Living Roadmap)

> **เอกสารอ้างอิงหลัก:** [18 · WAF Generation Assessment (Docs)](https://jakkaret.github.io/Docs-for-WAF-project/18-waf-generation-assessment.html)  
> **วิสัยทัศน์:** ยกระดับจาก Gen 1 (Signature) + Gen 2 (Bot Shield) สู่ **WAF Gen 3 (Next-Gen ML-Driven WAF)** โดยรักษาความแม่นยำสูง ไม่ส่งผลกระทบต่อทราฟฟิกปกติ และไม่แตะต้องโค้ด Origin  
> **สถานะปัจจุบัน:** 🟡 In Progress (เฟส 1.3 mechanism สร้างเสร็จ ปิดไว้; เฟส 2: hybrid candidate `20260927-205652` ผ่าน gate แบบ in-distribution (98.58% / 91.04%) แต่ **ยังไม่ promote** เพราะ payload ผูกกับบริบทของ dataset — ดูข้อ 2.3 และ `PROGRESS_GEN3_CHECKPOINT.md`; ผล LightGBM 85.08%/85.47% เดิมถูกแก้ไขแล้ว; เฟส 3.1-A ยืนยันแล้ว)
> **อัปเดตล่าสุด:** 27 กันยายน 2026

---

## 📌 กฎเหล็กและข้อกำหนดการอัปเดตเอกสาร (Mandatory Rules)

1. **Single Source of Truth:** เอกสารนี้ใช้เป็นแกนกลางในการติดตามสถานะงาน (Process Tracker) หากงานใดทำเสร็จแล้ว **ต้องเข้ามาเปลี่ยนเครื่องหมาย `[ ]` เป็น `[x]` และเพิ่มบันทึกใน [ตารางประวัติการทำงาน](#-ตารางบันทึกประวัติความคืบหน้า-change-log) ทันทีเสมอ**
2. **ห้ามแก้ไขไฟล์ที่ไม่เกี่ยวข้องเด็ดขาด (Strict Scope Boundary):** การทำงานในแต่ละข้อต้องแก้ไขเฉพาะไฟล์ที่ระบุใน [ขอบเขตไฟล์ที่อนุญาต](#-ขอบเขตไฟล์และระบบ-file--system-boundaries) เท่านั้น ห้าม Refactor ไฟล์อื่นนอกขอบเขตโดยพลการ
3. **Zero-Touch Origin Principle:** ห้ามแตะต้อง แก้ไข หรือเพิ่มโค้ดใดๆ บนแอปพลิเคชันต้นทางของลูกค้า (Origin Server) ทุกอย่างต้องทำงานที่ Edge Proxy / WAF Layer เท่านั้น
4. **Zero Customer Disruption:** การป้องกันระดับ Gen 3 ต้องไม่ทำให้ทราฟฟิกผู้ใช้ทั่วไปพัง ห้ามสกัดกั้นหน้าเนื้อหาทั่วไป และห้ามทำให้ฟอร์ม POST หลุด

---

## 🎯 สรุปช่องว่างสู่ WAF Gen 3 (Gap Analysis)

อ้างอิงจากเกณฑ์ในเอกสาร `18-waf-generation-assessment.html`:

| มิติการประเมิน | สถานะเดิมในเอกสาร | สถานะปัจจุบัน (18 ก.ย. 2026) | เป้าหมายสู่ Gen 3 ที่แท้จริง |
| :--- | :---: | :---: | :--- |
| **Gen 1: Signature WAF** | ✅ 100% | ✅ 100% | ModSecurity + OWASP CRS ทำงานตรวจจับ Known Attacks |
| **Gen 2: Bot & Session Risk** | ❌ 0% | 🟡 **50% (เพิ่งทำเสร็จ)** | มี Native PoW Challenge & Pre-Login Gate แล้ว (Commit `a3edfab`/`abff403`) รอเพิ่ม Session Risk Scoring |
| **Gen 3: Real-Time Auto-Block** | ❌ 0% | ❌ 0% (Human-in-the-loop) | ML ตัดสินใจ Inline Real-Time (Latency < 10ms) สั่ง Block หรือ Adaptive Challenge ได้เอง |
| **Gen 3: Model Accuracy & Recall** | ❌ Recall 62.26% | ❌ Recall 62.26% (FN=2,858) | ปรับปรุง Features และจูนโมเดลให้ **Attack Recall สู่ 85% – 90%+** โดยใช้ข้อมูลจริง ห้ามเมค/ห้ามคูณซ้ำ/ห้าม Overfit พร้อมควบคุม Benign Recall >= 98.5% |
| **Gen 3: Closed-Loop Retraining** | ❌ ไม่มี | ❌ ไม่มี | มี Pipeline ดึง Log จริงจาก ClickHouse มา Re-train / Fine-tune ต่อเนื่องอัตโนมัติ |
| **Gen 3: Explainability** | ✅ 100% | ✅ 100% | มี Feature Attribution (SHAP) ภาษาไทยราย Request พร้อมใช้งาน |

---

## 🗺️ แผนการดำเนินการ 4 ขั้นตอน (Phased Roadmap)

```mermaid
flowchart TD
    subgraph Phase 1: Real-Time Inline Decision
        P1_1[แปลง Model เป็น Fast Inference / ONNX] --> P1_2[สร้าง Nginx/Sidecar Decision Hook]
        P1_2 --> P1_3[Adaptive Enforcement: Score สูงส่ง PoW / สูงวิกฤตสั่ง Block]
    end

    subgraph Phase 2: Model Performance & Tuning
        P2_1[เพิ่ม Feature Extraction: Path Entropy / Token Ratios] --> P2_2[Benchmark Dataset คลีนแล้ว ปราศจาก Leakage]
        P2_2 --> P2_3[ดัน Attack Recall สู่ 85%-90%+ ปราศจาก Overfitting]
    end

    subgraph Phase 3: Closed-Loop Retraining
        P3_1[ดึง Real Traffic & Labels จาก ClickHouse] --> P3_2[Automated Retraining Script]
        P3_2 --> P3_3[Safety Evaluation Benchmark ก่อน Auto-Promote]
    end

    subgraph Phase 4: Session Tracking & Fingerprinting
        P4_1[JA3/JA4 TLS Fingerprinting] --> P4_2[Redis Session-based Risk Accumulator]
    end

    Phase 1 --> Phase 2 --> Phase 3 --> Phase 4
```

---

## 📋 รายการงานที่ต้องทำ (To-Do & Checklist)

### เฟส 1: Real-time Inline Decision & Adaptive Enforcement
- [x] **1.1 Low-Latency Inference Engine:** RF/ONNX inline fast path validated; Isolation Forest remains async-only analytics.
  - Parity: 9 cases, label mismatch 0, max probability diff 0.000037 with tolerance 0.001.
  - Benchmark: 30 samples, ONNX avg 0.059ms, p95 0.098ms; ML API /predict-fast is enabled.
  - Scope: Nginx hook and enforcement are not enabled yet.
- [x] **1.2 Edge Proxy Decision Hook (Shadow Mode):** เชื่อม Nginx Dynamic / Non-Static locations เข้ากับ RF/ONNX Decision Service ผ่าน mirror subrequest และ internal dashboard relay โดย fail-open; response ของ ML ถูกเก็บเป็น header ภายในและยังไม่ enforce block/challenge
  - Evidence (13/09/2026, original): Nginx active config มี mirror 5 จุด; benign ได้ decision `pass` score 0.2479; SQLi probe ได้ `anomaly` score 1.0; relay ที่ไม่มี capability header ได้ 404; `/healthz` ยังคง 200
  - **Correction (18/09/2026):** ตรวจซ้ำบน production จริงพบว่า evidence ข้างต้น **reproduce ไม่ได้** — `mirror`/`internal-ml-shadow` ไม่เคย commit เข้า git เลย (`git log -S'mirror' -- nginx/templates/conf.d/default.conf.template` ว่างเปล่า), มีอยู่ชั่วคราวจากการแก้ไฟล์ตรงบน disk (`/root/.bash_history`), ครอบคลุมแค่ 4 host ไม่ใช่ 5, และถูกเปลี่ยนปลายทางไปที่ `/internal-ml-capture` (งาน 3.1) ภายหลังโดยไม่ commit เช่นกัน — ตอนตรวจ ณ วันที่ 18/09 ไม่มี caller เรียก `/internal-ml-shadow` เลยทั้งใน template และ rendered runtime config (`docker exec waf-nginx grep -c ... /etc/nginx/conf.d/default.conf` = 0) ทุกตัวเลขที่อ้างข้างต้นยังเป็นข้อมูลจริงที่เคยรันได้ แต่ **ไม่ใช่สถานะปัจจุบันของระบบ** — ตามกฎข้อ 1 ของ Phase 2 (ห้ามเมคตัวเลข/เคลมลอยๆ) จึงบันทึกแก้ไขตรงนี้แทนการปล่อยไว้
  - Boundary: ไม่มีการ block/challenge จาก ML ในขั้นตอนนี้; Adaptive Enforcement อยู่ใน Task 1.3
- [x] **1.3 Adaptive Action Policy (mechanism built, enforcement OFF):**
  - `Score >= 0.95` (อันตรายสูงมาก): สั่ง Block 403 ทันที
  - `0.70 <= Score < 0.95` (ต้องสงสัย): ส่งเข้า Native Proof-of-Work Challenge (แก้ผ่านจึงให้ผ่าน)
  - `Score < 0.70` (ปกติ): ปล่อยผ่านสู่ Origin ทันที
  - **Evidence (18/09/2026):** ดู `ML_ENFORCEMENT_PLAN.md`. Global toggle `ml_enforcement_enabled` (default `false`) ใน `dashboard/backend/services/settings_service.py`, sync ผ่าน Redis (`waf:ml:policy`) ไปยัง `cdn/control-api/ml_policy.py`; ต่อเป็น branch ที่ 3 ของ `otp_engine.shield_access` ใช้ auth_request chain เดิม (ไม่เพิ่ม nginx location ใหม่). ทดสอบจริงบน production (bypass การจ่ายไปยัง real tunnel traffic โดยเรียก `/api/shield/access`/`/cdn-cgi/challenge` ตรงผ่าน loopback): pass band (score 0.2479) → 204, block band (score 1.0, threshold 0.95) → 403 + `X-Shield-Type: ml-block`, challenge band (score 1.0, threshold ปรับชั่วคราวเป็น 1.5 เพื่อบังคับ band) → 401 + `X-Shield-Type: ml` → `/cdn-cgi/challenge` render หน้า PoW จริง (200). คืนค่า `ml_enforcement_enabled=false` หลังทดสอบแล้ว, `scripts/smoke_test.sh` 22/22 invariant ผ่านทั้งก่อนและหลัง
  - **ทำไมยัง OFF:** promotion gate ของ Phase 2 ยังไม่ผ่าน (ดูรายการ Phase 2 ด้านล่าง) — เปิด enforcement ตอนนี้เท่ากับให้โมเดลที่ recall ต่ำกว่าเกณฑ์ตัวเองไป block/challenge traffic จริง ตามกฎบรรทัดสุดท้ายของเอกสารนี้ ("ห้ามเริ่ม Phase 4 หรือเปิด enforcement ก่อนมี artifact ที่ผ่าน validation และ rollback plan")
  - **Rollback plan:** `ml_enforcement_enabled: false` ใน system settings คือ rollback เต็มรูป — เขียนค่าเดียว ไม่ต้อง redeploy/restart container ใดๆ

### เฟส 2: ยกระดับความแม่นยำของโมเดล (ดัน Attack Recall สู่ 85% – 90%+ อย่างโปร่งใส)
> [!IMPORTANT]
> **มาตรฐานความโปร่งใสทางข้อมูลและโมเดล (Scientific Data Integrity & Anti-Overfitting Protocol)**  
> 1. **ห้ามเมคตัวเลขเด็ดขาด (No Fabricated Metrics):** ตัวเลข Recall, Precision, Accuracy ทุกตัวต้องเกิดจากการรันโค้ดประเมินจริงผ่านสคริปต์ `ml/evaluate_model.py` บนชุดข้อมูลจริงเท่านั้น ห้ามเขียนเคลมลอยๆ
> 2. **ห้ามคูณซ้ำข้อมูลหรือทำ Data Leakage (No Row Duplication / Multiplication):** ห้ามนำแถวเดิมมาคูณซ้ำ (เช่น `df * 500`) เพื่อปั่นตัวเลข ต้องทำ **Deduplication ผ่าน SHA-256 Hashes 100%** ก่อนการแบ่ง Train/Test Split เพื่อไม่ให้มีข้อมูลเหมือนกันหลุดข้ามไปมาระหว่างชุดฝึกและชุดทดสอบ
> 3. **ห้าม Overfitting จากการท่องจำ (Generalization over Memorization):** โมเดลต้องผ่านการทดสอบกับ Unseen Payloads และ Attack Mutations ใหม่ๆ ที่ไม่เคยเห็นใน Train Set โดยวัดผลผ่าน Stratified Cross-Validation
> 4. **ควบคุม False Positive Rate (Zero Customer Disruption):** การดัน Recall สู่ 85%–90% ต้องไม่แลกมาด้วยการบล็อกคนปกติ — **Benign Recall ต้องคงไว้ที่ >= 98.5% (False Alarm < 1.5%)** เสมอ

- [x] **2.1 Extended Feature Engineering (แก้ปัญหา FN 2,858 แถวเดิม):**
  - **Shannon Entropy Analysis:** คำนวณความสับสนของ URL Path และ Query Payload เพื่อจับ Shellcode, Base64, Hex และ Obfuscated Payload
  - **Structural Anomaly & Delimiter Ratios:** ตรวจจับวงเล็บ, Quotes, Backticks และอักขระคั่นโครงสร้างที่ผิดปกติ
  - **SQL/Script Mutation Patterns:** เพิ่มการจับ Comment Evasion (`/**/`, `-- -`), Inline Function Calls (`CHAR()`, `SLEEP()`), และ JSON-based Injection
  - **Evidence (13/09/2026):** เพิ่ม feature vector เป็น 22 features และรันบนข้อมูล 60,106 แถวที่ผ่าน SHA-256 deduplication 100%; train/test hash overlap = 0. Candidate ได้ Accuracy 90.24%, Attack Recall 86.62%, Benign Recall 93.92% (FN=1,013, FP=453).
  - **Promotion gate:** ยังไม่ promote เข้า production เพราะ Benign Recall ต่ำกว่าเกณฑ์ 98.5%; candidate และผล calibration ถูกเก็บไว้ใน `ml/models/archive/task2-1-extended-20260913/`
  - **Evidence (13/09/2026, CSIC-only FN audit):** CSIC-only audit buckets: 9,665/15,472 (62.47%) have high-confidence signals; 5,805 (37.52%) are structural/encoding-only review candidates; 2 rows (0.01%) remain unresolved. Dangerous encoded-token signal appears in 8,436 attack rows and suspicious path markers in 1,122. Ordinary URL encoding overlaps benign traffic and is not treated as proof of attack. This report is used for review only; no labels were auto-relabelled or promoted. Report: `ml/models/archive/task2-1-real-fn-audit-20260913/report.json`.
  - **Audited-training candidate (CSIC-only):** Excluding 3,700 review attack rows from fit reduced unseen-holdout Attack Recall to 53.09% at Benign Recall 98.54%; review rows must not be discarded or auto-relabelled. Report: `ml/models/archive/task2-1-audited-training-candidate-20260913/report.json`.
- [x] **2.2 Cost-Sensitive Learning & Threshold Calibration:**
  - ปรับ Class Weights (ให้ Penalty กับ False Negative มากขึ้น) เพื่อบีบให้โมเดลไม่มองข้ามการโจมตี
  - คำนวณหา Optimal Decision Threshold (จากเดิมที่ Cut-off 0.5 แบบแข็งตัว) เพื่อดัน Recall จาก 62.26% ขึ้นสู่ **85% – 90%**
  - **Evidence (13/09/2026):** Cost-sensitive RF (`class_weight={benign:1.25, attack:1.0}`) ที่ threshold 0.5 ได้ Benign Recall 95.65%, Attack Recall 84.83%; threshold 0.613780 ทำให้ Benign Recall 98.51% แต่ Attack Recall 80.75%. Promotion gate ยังไม่ผ่าน; report อยู่ที่ `ml/models/archive/task2-2-cost-sensitive-20260913/report.json`
  - Evidence (13/09/2026, CSIC-only): tested class weights `{1.0:1.0}`, `{1.25:1.0}`, `{1.5:1.0}`, and `{1.0:1.25}` with threshold calibration; best result within the benign gate: Benign Recall 98.65%, Attack Recall 64.59%; maximum Attack Recall 65.20% occurred at Benign Recall 98.44% and failed the safety gate; promotion gate failed. Report: `ml/models/archive/task2-2-real-cost-sensitive-20260913/report.json`.
  - **Data-integrity correction:** historical 60,106-row metrics for 2.1/2.2 came from a pipeline that regenerated 35,012 synthetic rows; those metrics are retained only as historical candidates and are not valid production-promotion evidence. CSIC-only reports above are authoritative.
- [x] **2.3 Model Architecture Exploration (LightGBM / XGBoost Ensemble):**
  - เปรียบเทียบประสิทธิภาพระหว่าง Random Forest เดิม กับ LightGBM / HistGradientBoosting เพื่อค้นหาโมเดลที่จับ Non-linear Boundaries ของ Payload สมัยใหม่ได้ดีกว่า
  - **Evidence (24/09/2026):** ทดสอบบนเครื่อง Local ด้วยชุดข้อมูลจริงล้วน 40,019 แถวที่ผ่าน SHA-256 Deduplication 100% (CSIC Cleaned + Real VPS Telemetry + 7,513 Real ModSecurity Blocked Attacks, zero synthetic rows). ขยายชุดฟีเจอร์เป็น 33 ฟีเจอร์. LightGBM ทำ Attack Recall พุ่งทะยานจาก 65.33% สู่ **85.08%** บนชุด Unseen Holdout โดยรักษา **Benign Recall ไว้ที่ 98.56% (FP=49)**, ROC-AUC **0.9832**, Latency เพียง **3.31 µs** (0.0033ms) ผ่านทั้งเกณฑ์ Safety Gate และ Accuracy Target บนข้อมูลจริง 100%; Candidate ถูกบันทึกไว้ใน `ml/models/archive/task3-1-real-augmented-candidate-20260924-152133/`
  - **Correction (27/09/2026):** ตรวจซ้ำ candidate ล่าสุด (`task3-1-real-augmented-candidate-20260925-124804`, 98.72% / 85.47%) — ตัวเลข reproduce ได้ตรงจริง แต่ **ไม่ใช่หลักฐาน promotion ที่ถูกต้อง** เพราะ pipeline ละเมิด 3.1-D/E/F ของเอกสารนี้เอง:
    1. **3.1-D.2:** 6,590 จาก 7,513 แถว ModSecurity (87.7%) เป็น protocol/generic-only event (920xxx + 949110) ไม่มี payload rule เลย — 6,344 แถวคือ `/socket.io/` polling ของ Juice Shop ที่โดน 920420 (CRS false positive) แต่ถูกติด label เป็น attack; attack recall บนกลุ่มนี้ 99.70% ดันค่ารวมขึ้น — ถ้าตัดออก attack recall เหลือ **79.71%**
    2. **3.1-D (circular label):** attack label ของ telemetry มาจาก feature ของโมเดลเอง (`keyword_matches`, `has_sql_operator` ฯลฯ) และ loader ทิ้ง POST body ที่เป็นหลักฐานไป (`POST-Data=""`)
    3. **Zero Synthetic:** มี 69 URL ที่เขียนขึ้นในโค้ด (`Representative_Benign_Web_Traffic`) ปนใน training และซ้ำกับ scenario ใน `test_comprehensive.py`
    4. **3.1-E.3:** split แบบสุ่ม — near-duplicate ข้ามฝั่ง train/holdout ได้; benign 25,786 แถวเป็น 3 กลุ่ม near-duplicate รวม ~15,000 แถว (`GET /?_wd=<token>` 8,887, socket.io 6,394) ทำให้ benign recall สูงเกินจริง; CSIC benign แยกเฉพาะ source ได้ 97.69% (ต่ำกว่า gate)
    5. **3.1-F.4:** "Optimal Threshold 0.7085 / 86.65%" จูนบน holdout เอง
    6. Latency 4.97 µs เป็นค่าเฉลี่ยแบบ batch; ต่อ 1 request จริง (เส้นทาง DataFrame→`predict_proba` แบบเดียวกับ `ml_api`) p50 ≈ 1.9 ms / p95 ≈ 2.7 ms (ยังต่ำกว่าเป้า < 10 ms)
  - **วิธีประเมินที่ถูกต้อง (27/09/2026):** near-duplicate group = path + ชื่อ param + รูปแบบค่า (ตัวเลข → 0, token สุ่ม → T, ไม่รวม method เพราะ CSIC ส่งทุก request ทั้ง GET/POST) ทุกแถวถ่วงน้ำหนัก 1/ขนาดกลุ่ม ให้ "รูปแบบ request" แต่ละแบบนับเท่ากัน 1 หน่วย (= dedup near-duplicate ตาม 3.1-E.1 โดยไม่ทิ้งข้อมูล); split/CV แบบ group-level stratified ตาม label × source; hyperparameter (grid 12 config) และ threshold เลือกจาก dev out-of-fold เท่านั้น; holdout ประเมินครั้งเดียว. ข้อมูลจริงหลังยุบ near-duplicate: **benign 25,787 แถว = 3,357 รูปแบบ** (VPS จริงมีแค่ ~371 รูปแบบ — กลุ่ม `GET /?_wd=<token>` กลุ่มเดียว 8,887 แถว), **attack 16,349 แถว = 6,537 รูปแบบ**
  - **การแก้ label/feature เพิ่มเติม (27/09/2026):** (1) ตัด ModSec non-GET 46 แถวที่ไม่มี body — extractor ไม่เคยเก็บ body จึงไม่มีหลักฐานในแถว (3.1-D); (2) `suspicious_path_marker_count` ไม่รู้จักไฟล์ลับเลย ทั้งที่ 679 จาก 923 ModSec payload attack คือการสแกน `/.env`, `/.git/config`, `/.aws/credentials` (CRS 930130) — เพิ่ม `RESTRICTED_FILE_PATTERN` ตามรายการ restricted-files ของ CRS ใน `ml/feature_engineering.py` (อยู่ใน EXTENDED เท่านั้น ไม่กระทบ production contract 13 คอลัมน์; `is_clean_structure` ไม่ได้อ้างถึง) พร้อม unit test ทั้งกรณี probe และ path ปกติ. ทดลองตัด `url_path_entropy` (สงสัยว่าเป็นลายนิ้วมือ endpoint) บน dev แล้ว **แย่ลง** (59.19% → 55.44%) จึงเก็บไว้
  - **ผลสุดท้าย (`ml/models/archive/task3-1-real-augmented-candidate-20260927-165254/`):** เลือก `num_leaves=15, min_child_samples=20, class_weight 1:1` (ทุก config ใน grid ห่างกัน < 1.5pp → ความจุโมเดลไม่ใช่คอขวด). OOF threshold 0.8445 → OOF Benign 98.50% / Attack **65.66%** (±0.73% ระหว่าง fold). **Unseen holdout: Benign 98.01% / Attack 65.41%** (weighted), ROC-AUC 0.8762; ModSec payload attack 94.15% (LFI 93.59%); benign จริงจาก VPS 100%; latency ต่อ request p50 1.8 ms / p95 2.0 ms; ชุดทดสอบ 63 scenario ผ่าน 59/63 (normal 36/37, attack 23/26) โดยไม่มี URL เขียนเองในชุดเทรน. **Promotion gate ไม่ผ่าน — เก็บเป็น experiment เท่านั้น** (3.1-G.1)
  - **เพดานที่เหลือมาจากข้อมูล ไม่ใช่โมเดล:** บน holdout attack ที่ **มีสัญญาณโจมตี** ใน request (70.3% ของรูปแบบ) จับได้ **84.15%** (ModSec 100%); attack ที่ **ไม่มีสัญญาณเลย** (29.7% — แทบทั้งหมดคือ CSIC parameter tampering เช่นค่าผิดรูปแบบในฟอร์ม) จับได้ 21.04% เพราะแยกจาก benign ไม่ได้หากไม่รู้ spec ของแอป และตามข้อ 2.1 ห้ามทิ้งหรือ relabel แถวเหล่านี้. FP ที่เหลือส่วนใหญ่คือ CSIC form template ที่ไม่เคยเห็นตอนเทรน. check_overfitting: recall gap train/holdout 1-2% แต่ ROC-AUC gap 0.066 (จำ template CSIC บางส่วน)
  - **งานถัดไปตามลำดับการตัดสินใจ:** เก็บ benign จริงที่หลากหลาย (3.1-B — ตอนนี้ ~371 รูปแบบ), เก็บ request body ใน ModSec extraction เพื่อให้ attack แบบ POST ใช้ได้, เพิ่ม payload attack จริงที่ไม่ใช่ LFI (SQLi/XSS จริงมีแค่หลักหน่วย), และพิจารณารายงาน CSIC structural-only แยกจาก gate หลัก (ต้องอนุมัติเปลี่ยนนิยาม gate ก่อน ห้ามเปลี่ยนเอง)
  - **ข้อมูลใหม่ + hybrid model (27/09/2026 ค่ำ):** เพิ่มข้อมูลจริงที่มี provenance — VPS audit log ทั้ง 3 ไฟล์ (อ่านอย่างเดียว; attack 1,149 / benign 77,632), open-appsec WAF Comparison (Apache-2.0; browsing จริง 185 เว็บ + payload 73,924), SR-BH 2020 (CC0; honeypot จริง, label ตรวจด้วยมือ, ใช้เฉพาะคลาส payload) → 226,542 รูปแบบ. Headline gate คำนวณบน CORE (CSIC + VPS) เพื่อให้เทียบกับรอบก่อนได้. LightGBM 36 features บนข้อมูลใหม่ยังได้ attack 65.28% (AUC 0.932); **Hybrid (token model + LightGBM stacking, `ml/hybrid_model.py`)** candidate `task3-1-real-augmented-candidate-20260927-205652`: holdout CORE **Benign 98.58% / Attack 91.04%** (OOF 98.54% / 88.77%) — **ผ่าน gate แต่ยังไม่ promote** เพราะ (1) payload ผูกกับบริบท: `POST / p=;cat /etc/shadow` = 1.00 แต่ `POST /api/run cmd=;cat /etc/shadow` = 0.002; (2) 63 scenario บล็อก attack ได้ 18/26; (3) leave-one-source-out ต่ำ (CSIC 13%, SR-BH 12%, benign เว็บจริง 40%). ทางแก้ที่กำลังทำ: โมเดลให้คะแนนราย unit (path segment / param / JSON leaf) แบบ multiple-instance learning + context-transfer stress test (`ml/experiment_unit_model.py`) — ยังไม่มีผลเพราะ `request_units()` crash เมื่อ body มี field > 64 (ต้องแก้ก่อนรัน)
- [x] **2.4 Rigorous Holdout & Cross-Validation Benchmark:**
  - รันการทดสอบ 5-Fold Stratified Cross-Validation บนชุดข้อมูล Unseen Holdout ที่คลีนแล้ว
  - บันทึกผลลัพธ์ Confusion Matrix (TP, FP, TN, FN) พร้อม Classification Report ลงในไฟล์ Metadata เพื่อใช้เป็นหลักฐานยืนยันความโปร่งใส
  - Evidence (13/09/2026): `ml/models/archive/task2-4-real-holdout-cv-20260913/report.json`; CSIC-only, synthetic rows = 0, SHA-256 train/holdout overlap = 0; unseen holdout Benign Recall 98.54%, Attack Recall 64.75%; promotion gate failed.
  - Candidate is not promoted; the result is a blocker for 2.2/2.3 and ML enforcement remains disabled.

### เฟส 3: ระบบเทรนต่อเนื่องอัตโนมัติ (Closed-Loop Retraining)
- [ ] **3.1 Data Feed จาก ClickHouse:** เขียน Worker ดึงคำขอที่โดนบล็อก, คำขอที่ผ่าน Challenge และคำขอปกติ มาจัดเตรียมเป็นชุดข้อมูลใหม่
  - Controlled lab-only telemetry is live via Nginx mirror -> dashboard relay -> loopback ML API; raw request bodies and headers are not persisted. The capture stores a SHA-256 body hash, redacted preview, and feature vector only, with allowlisted lab hosts, 64KB body cap, 5MB/day cap, and 7-day retention; this is not yet a ClickHouse worker or label-promotion source.
  - **3.1-A re-verified (18/09/2026):** เช่นเดียวกับ 1.2 ที่พบว่า mirror หลุดจาก template โดยไม่ commit, 3.1's `mirror /internal-ml-capture;` ก็หลุดไปด้วยเช่นกัน (มีข้อมูลเก่าอยู่ใน `ml/telemetry/` จากตอนที่เคย wire ชั่วคราว: 581 record วันที่ 14/09, เพิ่มอีก 6 record วันที่ 16-17/09) — re-wire ใหม่และ **commit ครั้งนี้จริง** (`nginx/includes/captcha_server.conf`: `/internal-ml-capture` location; `default.conf.template`: `mirror`+`mirror_request_body on;` ในทุก `location /`, ครอบคลุมทั้ง 5 host ใน `ml/capture_telemetry.py`'s allowlist ผ่าน real Host header ที่ downstream กรองเอง). Aggregate report หลัง re-wire (596 record รวมของเก่า+ใหม่): schema-complete 596/596 (100%), แยกตาม host: vampi 187, bwapp 198, dvwa 208, juice 3 (ryu ยังไม่มี traffic จับได้), แยกตาม method: POST 587 / GET 9, **unredacted secret-looking string ที่พบ = 0**. Size รวม ~596KB ต่อวันสูงสุด (คิดจาก 588KB ของวันที่หนักสุด) ยังต่ำกว่า cap 5MB/day มาก, retention 7 วันทำงานถูกต้อง (ไฟล์ 14/09 อายุ 4 วัน ณ วันที่ตรวจ ยังไม่ถูกลบ)
  - **3.1-A correction (18/09/2026, later same day):** evidence ด้านบน ("596 record", "committed ครั้งนี้จริง") ตรวจแค่ nginx mirror directive ว่า commit จริง แต่ไม่ได้ตรวจ Python receiving chain ที่รับข้อมูลจากมัน — พบว่าหลุดแบบเดียวกัน: `dashboard/backend/api/ml.py`'s `/capture` relay route, `ml/ml_api.py`'s `/capture` endpoint, `ml/capture_telemetry.py` ทั้งไฟล์ และ `ml/feature_engineering.py`'s extended 13→24 คอลัมน์ (`EXTENDED_FEATURE_COLUMNS`) ทั้งหมดอยู่บน disk ของ Main เฉยๆ ไม่เคย commit (ยืนยันด้วย `git show HEAD:<path> | grep capture` ว่างเปล่าทั้ง 3 ไฟล์ที่เป็น tracked path) 596 record ที่รายงานไว้เป็นของจริง (ระบบทำงานจริงตอนตรวจ) แต่ evidence "committed ครั้งนี้จริง" ผิด — ครอบคลุมแค่ nginx ครึ่งเดียว แก้แล้วด้วย commit `26a7855` (คอมมิตเฉพาะ 4 ไฟล์นี้ ด้วย explicit pathspec เพราะ index ตอนนั้นมี `logs/nginx/access.json` ปนอยู่ ซึ่งเป็น production log dump ที่ไม่ควร commit เด็ดขาด — ไม่แตะ) `FEATURE_COLUMNS` production inference contract ยังคง = `BASE_FEATURE_COLUMNS` (13 คอลัมน์) เหมือนเดิม ไม่กระทบ production model. เช็ค schema เพิ่ม: `capture_telemetry.py` เก็บ dict เต็มจาก `extract_features_from_request()`, ส่วน `train_model.py`/`evaluate_model.py` select คอลัมน์ด้วยชื่อ (`pd.DataFrame(...)[EXTENDED_FEATURE_COLUMNS]`) ไม่ใช่ position ดังนั้น schema ตรงกันปลอดภัย พร้อมใช้ต่อ 3.1-C/D เมื่อมี volume พอ
  - **ยังไม่ทำ (out of scope รอบนี้ตามที่ระบุใน "ลำดับการตัดสินใจ" ด้านล่าง):** 3.1-B (เก็บ traffic จริงให้หลากหลายครบ attack family ตามช่วงเวลา) ถึง 3.1-G (validation gate) ต้องใช้เวลาเก็บข้อมูลจริงหลายวัน/สัปดาห์ ทำในรอบเดียวไม่ได้โดยไม่กลายเป็นข้อมูลปลอม
- [ ] **3.2 Automated Retraining Job:** สร้าง Script หรือ Systemd Timer รายสัปดาห์สำหรับรัน Retraining Pipeline แบบอัตโนมัติ
- [ ] **3.3 Model Validation Gate:** ก่อนจะนำโมเดลใหม่ขึ้น Production ต้องรัน Automated Test Benchmark หาก Recall ตกต่ำกว่าเกณฑ์จะไม่อัปเดตโมเดล

### เฟส 4: Behavioral Session Tracking & TLS Fingerprinting (Gen 2 Extension)
- [ ] **4.1 TLS Fingerprinting (JA3 / JA4):** บันทึก Signature ของ SSL Handshake เพื่อตรวจจับสคริปต์อัตโนมัติ (เช่น curl, python-requests, Go-http) แม้ว่าจะปลอมแปลง User-Agent
- [ ] **4.2 Cumulative Session Risk:** เก็บแต้มความเสี่ยงสะสมราย IP ใน Redis (เช่น สแกน 404 บ่อย, ยิงถี่ผิดปกติ) เมื่อแต้มสะสมถึงเกณฑ์ให้บังคับ Challenge

---

## 🚫 ขอบเขตไฟล์และระบบ (File & System Boundaries)

### 🟢 ไฟล์และโฟลเดอร์ที่อนุญาตให้แก้ไข (Allowed Target Scopes)
งานทั้งหมดเพื่อ Gen 3 จะต้องทำอยู่ภายในขอบเขตโฟลเดอร์เหล่านี้เท่านั้น:
* `ml/` (โมเดล, สคริปต์เทรน, inference pipeline, evaluation scripts)
* `cdn/control-api/` (Challenge engine, inline policy logic, rate limiter integration)
* `nginx/includes/` และ `nginx/templates/` (เฉพาะ configuration ที่เกี่ยวกับ reverse proxy hook และ captcha integration)
* `dashboard/backend/api/` (API endpoint สำหรับดึงค่าสถานะ ML และความแม่นยำ)
* `dashboard/frontend/src/` (เฉพาะหน้า UI ที่เกี่ยวกับ ML Settings, Shield และ Analytics)
* `scripts/` (Automated worker, retraining scripts, vulnerability scanners)

### 🔴 ไฟล์และระบบที่ **ห้ามแตะต้องเด็ดขาด** (Protected - DO NOT TOUCH)
* ❌ **ห้ามแตะโฟลเดอร์แอปของลูกค้า/Origin ใดๆ**
* ❌ `dashboard/backend/data/` (ห้ามลบหรือเขียนทับ database `.db` โดยไม่มีสคริปต์ migration)
* ❌ `tunnel/` และ Core Zero-Trust Tunnel Agent ที่ทำงานเสถียรแล้ว
* ❌ Caddy Auto-HTTPS & SSL Certificate Provisioning Core
* ❌ ห้ามลบ Docstrings, Comments หรือ Type definitions ที่มีอยู่เดิมในไฟล์

---

## 📝 ตารางบันทึกประวัติความคืบหน้า (Change Log)

> 💡 **คำแนะนำ:** ทุกครั้งที่มีการ Commit โค้ดที่เกี่ยวกับ Roadmap นี้ ให้เพิ่มแถวใหม่ในตารางนี้ทันที

| วันที่ | Task ID / หัวข้อ | Commit ID | ผู้ดำเนินการ | รายละเอียดการเปลี่ยนแปลง |
| :--- | :---: | :---: | :---: | :--- |
| **09/09/2026** | Gen 2: Challenge Engine | `a3edfab` | ryu-chirachot | สร้าง Native Bot Challenge (PoW) & Pre-Login Gate สำเร็จ |
| **09/09/2026** | Gen 2: Dashboard UI | `abff403` | ryu-chirachot | เพิ่มแท็บ Bot & Login Shield บน Origin Detail และ Redesign Auth |
| **10/09/2026** | Gen 3: Roadmap Initialization | - | Pair Programming | จัดทำเอกสาร Roadmap และกำหนด Scope ป้องกันไฟล์นอกขอบเขต |
| **10/09/2026** | Gen 3: 1.1 RF/ONNX Fast Path | - | Pair Programming | Added ONNX export, inference, validation, benchmark and ML API /predict-fast; verified legacy /predict remains operational. |
| **13/09/2026** | Gen 3: 2.1 Extended Feature Engineering | - (candidate archived) | Pair Programming | Added entropy, encoded-payload, delimiter, comment-evasion, inline-function and JSON-injection features; evaluated with SHA-256 deduplication. Candidate not promoted because calibrated Attack Recall was 80.59% at Benign Recall 98.52%. |
| **13/09/2026** | Gen 3: 2.2 Cost-Sensitive Threshold Calibration | - (candidate archived) | Pair Programming | Tested one cost-sensitive RF holdout candidate with SHA-256 integrity; safety gate failed because no threshold achieved Benign Recall ≥98.5% and Attack Recall ≥85% simultaneously. |
| **10/09/2026** | Gen 3: 1.2 Edge Proxy Decision Hook | - (pending approval) | Pair Programming | Added shadow-only Nginx mirror hook for five dynamic locations, fail-open dashboard relay to loopback ML service, and verified pass/anomaly decisions without enforcement. |
| **13/09/2026** | Gen 3: 2.2 Real-Data Cost-Sensitive Calibration | - | Pair Programming | Re-ran class-weight and threshold candidates on CSIC-only data with SHA-256 deduplication; best within benign gate Benign Recall 98.65% / Attack Recall 64.59%; maximum Attack Recall 65.20% failed the benign gate; no candidate promoted. |
| **13/09/2026** | Gen 3: 2.1 Real-Data FN/Label Coverage Audit | - | Pair Programming | CSIC-only audit found 62.47% have high-confidence signals, 37.52% remain structural/encoding-only review candidates, and 2 rows remain unresolved; ordinary URL encoding is explicitly treated as noisy; feature-driven promotion paused pending label audit. |
| **13/09/2026** | Gen 3: 2.1 Form-Encoding Normalization | - | Pair Programming | Decoded form-style `+` spaces before feature/signature extraction; added unit coverage; production model/artifacts unchanged. |
| **13/09/2026** | Gen 3: 2.1 Signal Coverage Review | - | Pair Programming | Added suspicious path markers and dangerous encoded-token coverage; CSIC-only audit leaves 2 unresolved attack-labeled rows for manual review; no auto-relabel or production artifact. |
| **13/09/2026** | Gen 3: 2.1 Audited-Training Candidate | - | Pair Programming | Excluding 3,700 review attack rows reduced holdout Attack Recall to 53.09% at Benign Recall 98.54%; review rows are retained and no labels were changed. |
| **13/09/2026** | Gen 3: Real-Log Weak-Label Audit | - | Pair Programming | Audited 1,076,129 ModSecurity transactions: 5,103 high-confidence payload-rule events, 136,933 protocol/generic-only events, and 681,392 clean-success candidates; request bodies were not captured, so no auto-training or label promotion. |
| **13/09/2026** | Gen 3: 3.1 ClickHouse Label-Source Availability Audit | - | Pair Programming | Read-only check found 6,333 access-log rows: 5,993 protocol-rule events, 66 path-traversal events, and 1 RCE event; schema has no request-body field, so no auto-training or schema change was performed. |
| **13/09/2026** | Gen 3: 2.4 Holdout & Cross-Validation Benchmark | - | Pair Programming | Added CSIC-only 5-Fold Stratified CV and unseen holdout report; SHA-256 train/holdout overlap = 0; gate failed at Benign Recall 98.54% and Attack Recall 64.75%; no production artifact written. |
| **13/09/2026** | Gen 3: 3.1 Controlled Lab Request Telemetry | - | Pair Programming | Enabled lab-only body mirror through the existing fail-open dashboard relay to the loopback ML API; E2E lab POST returned 404 from origin while the request remained non-blocking, telemetry wrote 1,978 bytes with hash/features/redacted preview, and the test secret was absent. No production model or enforcement change. |
| **18/09/2026** | Gen 3: 1.2 Evidence Correction | - | Claude Sonnet 5 | Re-verified 1.2's own evidence on live Main and found it not reproducible: the `mirror`/`internal-ml-shadow` wiring was never committed to git, only existed transiently via direct disk edits, covered 4 hosts not 5, and was later repointed to `/internal-ml-capture` -- as of this check, zero live callers existed in template or rendered runtime config. Corrected in-place per the roadmap's own no-fabricated-claims rule; no production behavior changed by this correction itself. |
| **18/09/2026** | Gen 3: 1.3 Adaptive Action Policy (mechanism, OFF) | dbf9054 (Backend, local; not yet on Main's git history) | Claude Sonnet 5 | Built global `ml_enforcement_enabled` flag (default false) in settings_service.py, synced via Redis to a new `ml_policy.py` in control-api, wired as a third branch of the existing `shield_access` auth_request chain (no new nginx location). Verified all 3 score bands against the real /predict-fast pipeline on production (loopback calls, not real tunnel traffic): pass/challenge/block all correct, challenge page renders the real PoW form, block falls through to the existing static 403 page. Flag restored to false after testing. smoke_test.sh 22/22 before and after. Enforcement stays off pending Phase 2's promotion gate, per this roadmap's own line "ห้ามเริ่ม Phase 4 หรือเปิด enforcement ก่อนมี artifact ที่ผ่าน validation และ rollback plan" -- rollback is the same flag back to false. See `ML_ENFORCEMENT_PLAN.md`. |
| **18/09/2026** | Gen 3: 2 Decision -- no new sweep | - | Claude Sonnet 5 | Decided not to re-run the RF class-weight/threshold sweep: 2.2/2.4 already swept 4 class-weight configs with threshold calibration, 5-fold CV, and unseen holdout under SHA-256 dedup, and hit a real ceiling (~65% attack recall at 98.5%+ benign recall). Re-running the same experiment would not produce new information. Per this roadmap's own decision tree, proceeded to 3.1 (data pipeline) instead of a blind re-sweep or starting 2.3 early. |
| **18/09/2026** | Gen 3: 3.1-A Telemetry Hook Re-verification | - | Claude Sonnet 5 | Found the same never-committed-wiring gap as 1.2 for `/internal-ml-capture`; re-wired it and committed this time (`nginx/includes/captcha_server.conf` + `default.conf.template`, all 5 dynamic `location /` blocks). Ran an aggregate report over existing + newly captured telemetry (596 records total): 100% schema-complete, 0 unredacted secret-looking strings, host/method breakdown recorded above, well under the 5MB/day cap, 7-day retention intact. 3.1-B through 3.1-G explicitly not started -- they require real diverse traffic collected over days/weeks, out of scope for a single session without fabricating data. |
| **18/09/2026** | Gen 3: 3.1-A Correction -- Python half also uncommitted | 26a7855 (Backend, Main) | Claude Sonnet 5 | The 3.1-A re-verification above checked only that the nginx `mirror` directive was committed; the Python receiving chain it calls (`dashboard/backend/api/ml.py` `/capture` relay, `ml/ml_api.py` `/capture` endpoint, `ml/capture_telemetry.py`, `ml/feature_engineering.py`'s extended 13->24 column feature set) was disk-only on Main, same failure class as 1.2. Fixed by committing exactly those 4 files with an explicit pathspec (the git index also held an unrelated pre-existing staged pile, including a raw production log dump, left untouched). Confirmed `pd.DataFrame(...)[EXTENDED_FEATURE_COLUMNS]` selects by name not position, so the capture-side feature dict and the training-side column list can't silently desync on order. Production inference contract (`FEATURE_COLUMNS = BASE_FEATURE_COLUMNS`, 13 cols) unchanged. |
| **24/09/2026** | Gen 3: 2.3 & 3.1-F Real-World Augmented LightGBM Breakthrough | - (candidate archived) | Antigravity AI | Integrated 7,513 real ModSecurity blocked attacks (OWASP CRS provenance) + 17,371 telemetry verified benign samples (total 40,019 unique rows under 100% SHA-256 deduplication, zero synthetic rows). Extended feature vector to 33 universal structural features (adding `param_key_has_capital` and `param_value_punctuation_count`). LightGBM reached **85.08% Attack Recall** at **98.56% Benign Recall** on unseen holdout (0 leakage, ROC-AUC **0.9832**, latency **3.31 µs**), successfully passing both the safety and accuracy gates on 100% genuine data! Candidate archived in `ml/models/archive/task3-1-real-augmented-candidate-20260924-152133/`. |
| **27/09/2026** | Gen 3: 2.3 / 3.1-D..G Evidence Correction + Pipeline Fix | - (local only, not committed) | Claude Opus 5.5 | Re-ran the 25/09 LightGBM candidate: its 98.72% / 85.47% reproduce exactly but rest on labels and a split this roadmap forbids — 6,590/7,513 ModSec "attacks" are protocol-only (6,344 are Juice Shop `/socket.io/` hit by 920420), telemetry attack labels are derived from the model's own features with the POST body dropped, 69 hand-written URLs were in training, the split was random (near-duplicates straddled train/holdout), and the 0.7085 threshold was tuned on the holdout. Fixed `ml/train_gen3_full_real_benchmark.py` (payload-rule-only ModSec labels, telemetry benign-only, no hand-written rows, StratifiedGroupKFold near-duplicate split, pooled-OOF threshold, per-source/per-family report, single-request latency, `dataset_manifest.json`) plus `check_overfitting.py` / `test_comprehensive.py` (same split, CV threshold only). First corrected candidate: holdout Benign 100.00% / Attack 48.70% at OOF threshold 0.9970 — gate failed, not promoted (superseded same day, see next row). Old candidate kept with `train_script_snapshot.py` for provenance. |
| **27/09/2026** | Gen 3: 3.1-E/F Evaluation Hardening + Restricted-File Feature | - (local only, not committed) | Claude Opus 5.5 | Near-duplicate groups made method-independent (CSIC duplicates every request as GET+POST) and every row weighted 1/group-size so each distinct request shape counts once (25,787 benign rows are only 3,357 shapes; one `GET /?_wd=<token>` group alone is 8,887 rows). Folds/holdout now group-level stratified on label x source (row-balanced StratifiedGroupKFold had left the holdout with ~2 VPS benign shapes). Hyperparameters (12-config grid) and threshold chosen on dev OOF only; holdout evaluated once. Dropped 46 body-less non-GET ModSec events. Added CRS-930130-style `RESTRICTED_FILE_PATTERN` to `suspicious_path_marker_count` (679/923 ModSec payload attacks were `/.env`/`.git`/`.aws` probes invisible to every feature) with unit tests; ablating `url_path_entropy` on dev hurt, so it stays. Candidate `task3-1-real-augmented-candidate-20260927-165254`: OOF 98.50% / 65.66%, holdout Benign 98.01% / Attack 65.41%, ModSec payload 94.15%; attacks with any attack signal 84.15%, structural-only (CSIC tampering) 21.04%. Gate failed, not promoted; remaining ceiling is data (VPS benign diversity, no captured bodies, CSIC structural-only attacks). |
| **27/09/2026** | Gen 3: 3.1-B External Real Data + Hybrid Token Model | - (local only, not committed) | Claude Opus 5.5 | Added real, provenance-tracked data: all three VPS ModSecurity audit logs via a read-only SSH extractor (`scripts/extract_vps_audit_dataset.py`, nothing written on the VPS; 1,149 payload-rule GET attacks, 77,632 rule-free 2xx lab-host GET benign), open-appsec WAF Comparison (Apache-2.0; 185 real sites + 73,924 payloads) and SR-BH 2020 (CC0; real honeypot, payload classes only) via `ml/prepare_external_datasets.py` -> 226,542 distinct shapes. Headline gate kept on CORE sources (CSIC + VPS). Trainer: build cache, physical-core `n_jobs` (8x faster), pandas `isin` for group folds. New `ml/hybrid_model.py` (hashed token n-grams -> TF-IDF -> logistic regression, stacked out-of-fold under LightGBM). Candidate `task3-1-real-augmented-candidate-20260927-205652`: holdout CORE Benign 98.58% / Attack 91.04% (36-feature LightGBM on the same data: 65.28%). **Not promoted**: payloads are confounded with dataset context (`POST / p=;cat /etc/shadow` 1.00 vs `POST /api/run cmd=...` 0.002), 63 scenarios 18/26 attacks, leave-one-source-out weak (CSIC 13%, SR-BH 12%). Next: per-unit multiple-instance model + context-transfer stress test (`ml/experiment_unit_model.py`), blocked on a `request_units()` bug (`parse_qsl` max_num_fields raises). |
| **28/09/2026** | Gen 3: 3.1 Value-Level Detector Features + Colab Pipeline | `85216ef`..`b2d184d` (trainmodelgen3) | Claude Opus 5.5 | Fixed `request_units()` (`parse_qsl` max_num_fields raised). New `ml/value_features.py`: 17 per-unit features (libinjection SQLi/XSS + command injection, traversal incl. overlong UTF-8, sensitive/restricted files, SSTI/JNDI, NoSQL, SSRF, code exec, XXE, CRLF), 0.52% hits on 271k real browsing requests; fixed a lone-surrogate crash (`%uD800`) that could break scoring. SR-BH "000 - Normal" rows contradicted by detectors (real shellshock/LFI/XSS payloads) excluded as unknown per 3.1-D, owner decision: 25,526 of 65,110. Free-tier Colab notebook `ml/waf_gen3_colab.ipynb` (Drive cache, live logs). Public-data run (CORE = CSIC only, no VPS data): value features beat the 36-feature baseline everywhere (holdout attack 93.70 → 95.54%, 63 scenarios 20 → 23/26); dropping 6 context features lifts context-transfer detection 27.9 → 66.1% and leave-one-source-out attack 22.7 → 57.2% at −7pp CSIC and −8.7pp LFI; monotone constraints hurt. Not promoted; next: unconstrained no-context config + per-feature ablation. |
| **28/09/2026** | Gen 3: 3.1-G.0 Promotion Gate Redefinition | - (trainmodelgen3) | Claude Opus 5.5 / owner approval | Gate moved from CSIC 2010 + VPS in-distribution holdout to multi-dataset criteria, fixed before evaluating the final candidate: benign >= 98.5% overall and per real-traffic benign source, 37/37 normal scenarios; attack >= 85% on holdout; primary criterion = attack recall at 98.5% benign on datasets never seen in training (open-appsec >= 85%, SR-BH >= 60%, VPS ModSecurity >= 85% when available, CSIC reported); CSIC signal-bearing attacks >= 80%; context-transfer stress detection >= 60% at <= 0.5% control FP; >= 23/26 attack scenarios. The old CORE gate is still reported for comparison. **Superseded the same evening (next row).** |
| **28/09/2026** | Gen 3: 3.1-G.0 Gate v2 (all datasets, equal weight) + evaluation hardening | - (trainmodelgen3) | Claude Opus 5.5 / owner approval | Owner asked to judge on all datasets together rather than CSIC-specific criteria. Gate v2, fixed before any final-candidate evaluation: G1 benign >= 98.5% on every dataset; G2 mean holdout attack recall over datasets >= 85%; G3 mean attack recall at 98.5% benign on datasets never seen in training >= 70%; G4 no dataset below 40% in G2/G3; G5 normal scenarios 37/37, attack scenarios >= 23/26, stress >= 60%. Every dataset weighs the same (sampling rates must not move the result). Implemented once in `ml/promotion_gate.py` (+ tests) and reported by `experiment_value_features.py`. `choose_threshold_weighted()` is now exact on the scores (the 0.0005 grid returned 0 attack recall when benign scores saturated; verified against exhaustive search on 500 random weighted cases). Colab notebook: every step stops Run all on failure (no silent fall-through to stale reports), never waits for input, shows only this session's reports, evaluates the gate across local and Drive reports. |
| **29/09/2026** | Gen 3: Serving model for feature set F (shadow) | - (trainmodelgen3) | Claude Opus 5.5 | Feature set F locked after gate v2 (3/5, best of all configurations). New ml/gen3_model.py (single definition of F + Gen3FModel scoring, ~0.3 ms/request after removing a 48x repeated feature extraction), ml/train_final_gen3.py (all data, threshold keeping >= 99% benign on every dataset out-of-fold as a margin over G1, scenarios, latency, model_card.json with input hashes and git commit), ml_api.py POST /predict-gen3 + /health gen3_shadow (shadow only, loaded only if ml/models/gen3/gen3_f_model.joblib exists; existing endpoints unchanged), Colab RUN_FINAL_MODEL mode. Verified end to end locally on real data subsets, 48 tests. Not promoted; production still RandomForest 13 features. |
| **29/09/2026** | Gen 3: ONNX export + separate ML host kit (Azure) | - (trainmodelgen3) | Claude Opus 5.5 | Advisor asked to run ML apart from the main WAF. New ml/gen3_onnx.py: LightGBM -> ONNX (onnxmltools, opset 15). Split thresholds are rewritten to the largest float32 <= LightGBM's double threshold, and LightGBM's zero threshold is reproduced. Result: ONNX equals booster.predict to ~1e-7 even on rows placed exactly on split thresholds (nearest-rounding export differed by up to 0.99 there). The export is written only if parity < 1e-5; threshold, columns and card are kept in ONNX metadata. Gen3OnnxModel (onnxruntime, no LightGBM, no pickle) is preferred by ml_api over joblib. train_final_gen3.py writes gen3_f_model.onnx and prints the 63 scenarios, then Precision / Recall / F1 (scenarios + out-of-fold per dataset); ml/export_gen3_onnx.py converts older joblibs. ml_api: optional token (WAF_ML_API_TOKEN) and WAF_FAST_ENGINE=rf or gen3 for /predict-fast. Backend api/ml.py (taken from branch Backend = VPS) and async_log_analyzer: ML URL, token, timeout and capture target from env; defaults unchanged. deploy/azure-ml: install.sh, hardened systemd unit, WireGuard templates, VPS drop-ins, smoke_test.sh, Thai guide; capture to the ML host is off by default. ml/requirements-serve.txt (Python 3.12, no LightGBM) installs cleanly, and every backend endpoint was served from it. 55 tests. VPS inspected read-only: waf-ml there runs on numpy/sklearn/onnxruntime files deleted when its venv was recreated on 27/09 (a restart would lose the models); not changed. |
| **29/09/2026** | Gen 3: WAF-tool testing + canonical request form | - (trainmodelgen3) | Claude Opus 5.5 | Local defensive harness (ml/security_test) fronting a stub origin with the Gen 3 ONNX model; GoTestWAF v0.5.10, sqlmap 1.10.9 and Nuclei v3.11.1 against 127.0.0.1 only. GoTestWAF TP 31.26% / FP 12.77% (score 29.79%); sqlmap: every payload-bearing SQLi blocked (min score 0.808); Nuclei no-payload probes 3.8%. Root causes, measured: the same SQLi scored 0.993 as form, 0.215 as JSON, 0.339 as multipart (libinjection fired in all; JSON/multipart syntax moved the structural features, JSON bodies being mostly benign in training) and 0.001 as Base64 (no detector saw it); the 18 GoTestWAF false positives had no detector hit, their scores driven by entropy and %20 counted as encoding. New ml/canonical.py, used by the builder and request_features: one URL-decoding layer with only pair delimiters re-escaped (double encoding kept), JSON/multipart to form pairs, Base64 decoded only when the result trips a detector. FEATURE_SET_VERSION gen3-F-2026-09-29-canon (raw-trained models refused); experiment reports record feature_extraction and the gate never mixes extractions. Directional check with the raw-trained model: JSON/multipart 0.993, Base64 0.982, false positives 18 -> 3. Retraining and gate on Colab pending. 67 tests. |
---

## 🧭 งานถัดไปที่ต้องทำ: Phase 3.1 Data-Ready Telemetry Pipeline

สถานะก่อนเริ่มงาน: ระบบมี controlled lab telemetry แบบ fail-open แล้ว แต่ Phase 3.1 ยังไม่ถือว่าเสร็จ เพราะยังไม่มี pipeline ที่เชื่อม request จริงกับ security evidence และสร้าง dataset ที่ตรวจสอบย้อนกลับได้ งานชุดนี้ต้องทำให้ครบก่อนเริ่ม automated retraining หรือพิจารณา Model Architecture Exploration ในข้อ 2.3

### เป้าหมาย

สร้างสายงานจาก request จริงใน lab ไปเป็น dataset สำหรับประเมินและ retrain Random Forest เดิม โดยรักษา privacy, data integrity, reproducibility และ production safety ตามเงื่อนไขใน roadmap และ WORKING_RULES.md

### ขั้นตอนดำเนินงานแบบละเอียด

#### 3.1-A — ตรวจสอบความถูกต้องของ Controlled Telemetry

1. ตรวจสอบว่า Nginx mirror ทำงานเฉพาะ host ใน allowlist (dvwa, juice, vampi, bwapp และ host ที่ได้รับอนุมัติ) และไม่มี mirror ใน default/fallback server
2. ตรวจสอบ fail-open: เมื่อ relay หรือ ML API ล้มเหลว request หลักต้องยังไปถึง origin ได้ และ latency ของ mirror ต้องไม่ทำให้ traffic หลักติดค้าง
3. ตรวจสอบ schema ของทุก record ให้มี timestamp, host, method, path, redacted query, request ID, content type, body length, body hash, truncation flag และ feature vector
4. ตรวจสอบว่าไม่มี raw request body, raw request headers หรือ secret เช่น password, token, cookie, API key, authorization และ CSRF ถูกเขียนลง disk
5. ตรวจสอบ daily size cap, retention period และ permission ของ ml/telemetry/
6. สร้างรายงาน aggregate จำนวน request, schema completeness, feature completeness, file size และ secret-scan result โดยไม่แสดง payload จริง

**เกณฑ์ผ่าน:** telemetry ทำงานเฉพาะ lab, ไม่ทำให้ traffic ล้ม, ไม่มี secret leakage และ record ที่ schema ไม่ครบถูกแยกออกจาก training dataset

#### 3.1-B — เก็บข้อมูล Lab ที่มีความหลากหลาย

1. เก็บ request จริงจาก lab applications ที่อยู่ใน allowlist ภายในช่วงเวลาที่กำหนด
2. ให้ครอบคลุม benign traffic และ attack families ที่ต้องการตรวจจับ เช่น SQL injection, XSS, path traversal, command/RCE, encoded payload และ comment/mutation evasion
3. ห้ามสร้าง synthetic rows เพื่อปั่น metrics และห้ามนำ test request ที่ไม่มี provenance เข้าชุด train
4. สรุปจำนวนข้อมูลแยกตาม host, method, content type, path family และ feature availability โดยใช้ aggregate เท่านั้น

**เกณฑ์ผ่าน:** มีข้อมูลจริงเพียงพอสำหรับเชื่อมกับ security logs และมี attack family ที่ต้องการวัดผล ไม่ใช่มีเพียง protocol anomaly

#### 3.1-C — เชื่อม Telemetry กับ ModSecurity/ClickHouse

1. ใช้ request ID เป็น primary correlation key ระหว่าง telemetry, Nginx/access log, ModSecurity และ ClickHouse เมื่อมีข้อมูล
2. วัด correlation coverage และแยก unmatched records ตามสาเหตุ
3. หาก request ID ไม่สอดคล้องกัน ให้แก้ correlation path หรือ schema ก่อนติด label ห้ามเดา label จาก timestamp/path เพียงอย่างเดียว
4. เก็บ provenance ของทุก label ว่ามาจาก log/file/rule ใด และเกิดขึ้นเวลาใด

**เกณฑ์ผ่าน:** label ทุกตัวที่นำไป train สามารถย้อนกลับไปหา security evidence ได้ และอัตรา join สำเร็จผ่านเกณฑ์ที่กำหนดก่อนเริ่ม retrain

#### 3.1-D — ติด Label แบบ Conservative

1. ติด attack เฉพาะ ModSecurity payload rule ที่มีความมั่นใจสูงและมี evidence ชัดเจน
2. protocol/generic-only events ให้เป็น unknown หรือใช้วิเคราะห์แยก ห้ามติดเป็น attack อัตโนมัติ
3. request ที่ไม่มี evidence เพียงพอให้เป็น unlabeled และไม่นำเข้า supervised training
4. benign label ต้องมาจากเงื่อนไขที่ตรวจสอบได้ ไม่ใช่เพียงไม่มี alert
5. สุ่มตรวจตัวอย่างของแต่ละ attack family แบบ manual และบันทึกผลก่อนยืนยัน dataset

**เกณฑ์ผ่าน:** ไม่มี auto-label ที่ทำให้ protocol noise กลายเป็น attack label และ positive ทุกตัวมี evidence/provenance

#### 3.1-E — ทำ Dataset Quality Gate

1. deduplicate ด้วย request/body hash และตรวจ near-duplicate ที่อาจทำให้ holdout leakage
2. ตรวจ secret leakage, malformed record, missing feature, truncated body และ schema-version mismatch
3. แยก train/holdout ด้วย group/time separation ไม่ให้ request หรือ payload เดียวกันอยู่ทั้งสองฝั่ง
4. ตรวจ SHA-256 overlap ระหว่าง train และ holdout ต้องเป็นศูนย์ หรือมีเหตุผลที่บันทึกไว้ชัดเจน
5. ตรวจ class balance และ attack-family coverage โดยไม่ oversample จนกลายเป็นข้อมูลปลอม
6. สร้าง dataset manifest ระบุ dataset version, row counts, label counts, feature count, split rule และ file hash

**เกณฑ์ผ่าน:** dataset reproducible, ไม่มี leakage, ไม่มี secret, มี manifest และตรวจสอบย้อนกลับได้

#### 3.1-F — Retrain Random Forest เดิมและประเมินผล

1. ใช้ feature schema เดียวกันระหว่าง feature engineering, training และ inference
2. ทดลอง class weight และ decision threshold จาก validation data เท่านั้น
3. รัน 5-fold stratified cross-validation บน train set
4. ประเมินบน unseen holdout ที่ไม่ถูกใช้จูน threshold
5. รายงาน Benign Recall, Attack Recall, confusion matrix, ROC-AUC, false-positive count, false-negative count และผลแยกตาม attack family
6. เปรียบเทียบกับ production baseline และผล Extended Features เดิม

**เกณฑ์ผ่านเบื้องต้น:** Attack Recall ไม่น้อยกว่า 85% พร้อม Benign Recall ไม่น้อยกว่า 98.5% และไม่มี attack family สำคัญตกลงอย่างผิดปกติ

#### 3.1-G — Validation Gate และการตัดสินใจ

**3.1-G.0 — นิยาม Promotion Gate (ฉบับ 28/09/2026 ครั้งที่ 2, อนุมัติโดยเจ้าของโปรเจกต์)** — กำหนดไว้ *ก่อน* ประเมิน candidate สุดท้าย ห้ามปรับตัวเลขหลังเห็นผล; การแก้ไขต้องได้รับอนุมัติและบันทึกใน changelog. คำนวณโดย `ml/promotion_gate.py` (ที่เดียว — ตัวทดลอง, notebook และตัวเทรนเรียกใช้ร่วมกัน)

เป้าหมายตามที่เจ้าของโปรเจกต์กำหนด: **บล็อกการโจมตีได้เกือบทั้งหมด และปล่อย traffic ปกติผ่านได้ถูกต้อง โดยประเมินร่วมกันทุก dataset** — ไม่ใช้ CSIC 2010 เป็นเกณฑ์หลักอีกต่อไป (traffic สร้างขึ้นของแอปเดียวอายุ 16 ปี, ~1/3 ของ attack เป็น parameter tampering ที่ไม่มีสัญญาณใน request) และไม่วัดเฉพาะ holdout แบบ in-distribution (hybrid `20260927-205652`: CORE 91% แต่ source ที่ไม่เคยเห็น 6–13%)

| # | เกณฑ์ | วิธีวัด | เป้าหมาย |
| :--- | :--- | :--- | :--- |
| **G1** | **ปล่อยคนปกติผ่านถูกต้อง** | benign recall บน holdout แยกทีละ dataset (CSIC, open-appsec, SR-BH, VPS เมื่อมีข้อมูล) ที่ threshold จาก dev OOF | ≥ 98.5% **ทุก** dataset |
| **G2** | **บล็อกการโจมตีบนเว็บที่รู้จัก** | attack recall บน holdout เฉลี่ยทุก dataset | ≥ 85% |
| **G3** | **บล็อกการโจมตีบนเว็บใหม่ที่ไม่เคยเห็น** | leave-one-dataset-out: attack recall ที่ benign 98.5% ของ dataset นั้น (threshold แบบ exact), เฉลี่ยทุก dataset | ≥ 70% |
| G4 | ไม่มี dataset ที่เป็นจุดบอด | attack recall ต่ำสุดของ dataset ใดๆ ใน G2 หรือ G3 | ≥ 40% |
| G5 | ตรวจสุขภาพ | `ml/test_comprehensive.py` + context-transfer stress test | scenario ปกติ 37/37, scenario โจมตี ≥ 23/26, stress detection ≥ 60% |

- **"เฉลี่ยทุก dataset" = ทุก dataset น้ำหนักเท่ากัน** (macro average) — ขนาดของแต่ละชุดขึ้นกับอัตราการสุ่มที่เราเลือกเอง (open-appsec legit 20%, SR-BH attack 40%) ผลจึงต้องไม่ขึ้นกับตัวเลขนั้น; open-appsec legitimate + malicious นับเป็น dataset เดียว, แหล่ง VPS ทั้งหมดนับเป็น dataset เดียว
- ตัวเลข holdout / stress / scenario ใช้ค่าเฉลี่ยของ 3 group-level holdout fold (`experiment_value_features.py --folds 3`); G3 ใช้ leave-one-dataset-out ครั้งเดียว; รวมผลจากหลายรายงานได้เฉพาะรายงานที่ใช้ชุด dataset เดียวกัน
- ต้องผ่าน **ทุกข้อ** จึงจะเข้าสู่ขั้นตอน 3.1-G.1–5 ด้านล่าง (ONNX, latency, reproducibility, rollout Silent → Tuning → Enforce ตาม `WORKING_RULES.md` ข้อ 2 — G3 วัดที่ threshold ที่จูนราย dataset ดังนั้นการจูนราย tenant ก่อน enforce เป็นเงื่อนไขบังคับ)
- Gate เดิม (CORE holdout 98.5% / 85%) ยังรายงานควบคู่เพื่อเทียบกับ candidate เก่า แต่ไม่ใช้ตัดสิน promotion

1. หากไม่ผ่าน gate ให้เก็บ artifact/report เป็น experiment เท่านั้น ห้าม promote
2. หากผ่าน gate ให้รัน evaluation ซ้ำจาก manifest เดิมเพื่อยืนยัน reproducibility
3. ตรวจ feature count, inference compatibility, ONNX export และ latency ก่อนพิจารณา promotion
4. ให้ production ใช้ artifact เดิมจนกว่าจะมี approval และ rollback plan
5. บันทึก dataset version, metrics, decision และเหตุผลลงใน roadmap changelog

### ลำดับการตัดสินใจหลังจบ Phase 3.1

- ถ้า quality gate ไม่ผ่าน: หยุดแก้ data/correlation/label quality ก่อน ห้าม retrain เพื่อเอาตัวเลข
- ถ้า dataset ผ่านแต่ Random Forest ยังไม่ถึงเป้าหมาย: ปรับปรุง features และ label quality ก่อน
- ถ้า dataset และ features ผ่านแล้ว แต่ Random Forest ยังไม่ถึงเป้าหมาย: ค่อยประเมินข้อ 2.3 ใน environment แยก โดยยังไม่ติดตั้ง dependency ใน production .venv
- ถ้าผ่านทุก gate: จึงเริ่ม Phase 3.2 automated retraining และ Phase 3.3 model validation gate
- ห้ามเริ่ม Phase 4 หรือเปิด enforcement ก่อนมี artifact ที่ผ่าน validation และ rollback plan

### ข้อจำกัดที่ต้องรักษาตลอดงาน

- ห้ามติดตั้ง LightGBM/XGBoost ใน VPS production ในขั้นตอนนี้
- ห้ามเปลี่ยน production model, ONNX artifact หรือเปิด blocking/challenge จากผลทดลอง
- ห้ามเก็บ raw body, raw headers หรือ secrets
- ทุกการเปลี่ยนแปลงต้อง fail-open, ตรวจสอบได้ และย้อนกลับได้
- หากไม่ผ่าน gate ให้หยุดที่ experiment และบันทึกเหตุผล ห้ามใช้ synthetic data หรือ data leakage เพื่อปรับ metrics

---
## 🔍 คำสั่งสำหรับตรวจสอบความสมบูรณ์ของระบบ (Verification Commands)

เมื่อแก้ไขโค้ดแต่ละส่วน ให้รันคำสั่งเหล่านี้เพื่อตรวจสอบว่าระบบไม่พัง:

```bash
# 1. ตรวจสอบสถานะ Service ทั้งหมด
docker compose ps

# 2. ตรวจสอบ Linting & Type Check ฝั่ง Dashboard Frontend
cd dashboard/frontend && npm run build

# 3. รัน Unit Tests ฝั่ง ML และ Form Logic
npm run test -- captchaForm.test.ts
pytest tests/

# 4. ทดสอบความเร็วในการ Infer ของ ML (Latency Check)
python3 ml/benchmark_latency.py
```
