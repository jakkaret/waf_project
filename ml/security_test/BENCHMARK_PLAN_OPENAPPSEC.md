# แผนเทียบระบบ WAF ของเรากับผลิตภัณฑ์อื่นด้วย open-appsec WAF Comparison

> สถานะ: **กำลังทำ — หยุดชั่วคราว 2 ต.ค. 2569** เพื่อย้ายไปรันบนเครื่องที่ RAM และ CPU มากกว่า
> ขั้นที่ 1 และ 3 เสร็จ · ขั้นที่ 2 (calibration) ได้ผลบางส่วน · ขั้นที่ 4–6 ยังไม่เริ่ม
> ทุกการทดสอบรันบน Docker ในเครื่อง ไม่แตะ VPS production และไม่มีค่าใช้จ่าย · branch `trainmodelgen3`

**เริ่มงานต่อบนเครื่องใหม่: ไปที่หัวข้อ 11 ได้เลย**

## 1. เป้าหมาย

วัดระบบของเราด้วยชุดทดสอบและเครื่องมือ **ชุดเดียวกับที่ open-appsec ใช้วัด 14 ผลิตภัณฑ์ในปี 2026**
แล้ววางตัวเลขของเราไว้ในตารางเดียวกัน (True Positive Rate, False Positive Rate, Balanced Accuracy)

เหตุที่เลือกชุดนี้เป็นตัวเทียบหลัก:

| เกณฑ์ | open-appsec WAF Comparison | GoTestWAF | SecureIQLab |
| :--- | :--- | :--- | :--- |
| รันเองได้ | ได้ (โค้ด Apache 2.0, malicious dataset MIT) | ได้ | ไม่ได้ (ชุด attack ของแล็บ) |
| มีผลของเจ้าอื่นให้เทียบ | 14 ผลิตภัณฑ์ ปี 2026 | ค่าอ้างอิงของ Wallarm (ไม่ระบุวันที่) | มี แต่รันซ้ำไม่ได้ |
| ขนาด | ปกติ 1,040,242 / โจมตี 73,924 | 816 request | ~1,600 attack |

ข้อควรระวัง: ผลที่เผยแพร่ทำโดย **Check Point** (เจ้าของ open-appsec) แต่เปิด dataset และเครื่องมือให้รันซ้ำได้

## 2. ข้อมูลที่ตรวจแล้ว

| รายการ | ค่า |
| :--- | :--- |
| Repo | https://github.com/openappsec/waf-comparison-project (commit ที่อ่าน: `8ec8263`, 11 ก.พ. 2026) |
| Docker image | `ghcr.io/openappsec/waf-comparison-project:latest` |
| Legitimate dataset | `https://downloads.openappsec.io/waf-comparison-project/legitimate.zip` · 1,203,983,791 bytes · last-modified 1 ธ.ค. 2024 · sha256 `58faee18…d778` |
| Malicious dataset | `https://downloads.openappsec.io/waf-comparison-project/malicious.zip` · 452,537 bytes · last-modified 17 ก.ค. 2023 · sha256 `131314e5…b7b2b` |
| ตัวเลือกของเครื่องมือ | `--waf-name`, `--waf-url` (หลายคู่ได้), `--max-workers` (ค่าเริ่มต้น 4), `--fast` (สุ่ม 15% seed 42), `--fresh-run` (ลบเฉพาะ DB/config/log ไม่ลบ dataset) |
| ผลลัพธ์ | `results/waf-comparison-report.pdf` + ฐานข้อมูล DuckDB `results/db/waf_comparison.duckdb` |

### วิธีที่เครื่องมือตัดสิน (อ่านจากโค้ด `helper.py`, `report/data_loader.py`)
- **บล็อก** = status **403** หรือหน้าเว็บมีข้อความ block page ของ F5 · status อื่น (200, 400, 404 …) = ไม่บล็อก
- **timeout 0.5 วินาที** ลอง 3 ครั้ง ถ้ายังไม่ได้ จะบันทึก status 0
- **request ที่ได้ status 0 ถูกตัดออกจากทั้ง TPR และ FPR** → ต้องรายงานจำนวนที่ถูกตัดทุกรอบ ถ้ามาก ผลเชื่อไม่ได้
- ก่อนเริ่ม เครื่องมือตรวจ: `GET <url>` ต้องได้ 200 และ `<url>/?a=<script>alert(1)</script>` ต้องโดนบล็อก ไม่งั้นหยุด
- ส่ง request ทีละไฟล์ ไฟล์ละระบบ (ระบบแรกครบก่อนแล้วค่อยระบบถัดไป) แล้วเขียนผลลง DuckDB

### dataset ที่นับจริงหลังแตกไฟล์
| ชุด | จำนวน |
| :--- | ---: |
| Legitimate | **1,040,242** request จาก **692 ไฟล์ (692 เว็บ)** — ตรงกับบทความปี 2026 |
| Malicious | **73,924** — บทความปี 2026 ระบุ 74,284 (ต่าง 360) |
| แยก malicious | xss 41,888 · traversal 28,314 · cmdexe 2,468 · sqli 916 · log4shell 220 · xxe 70 · shellshock 48 |

ข้อสังเกต: malicious เป็น **XSS + path traversal รวม 95%** มี SQLi แค่ 916 ตัว → TPR ของชุดนี้สะท้อนการจับ XSS/traversal เป็นหลัก

### ผลที่เผยแพร่ (open-appsec, ม.ค. 2026 แก้ไข ก.พ. 2026)

| WAF | การตั้งค่า | True Positive | False Positive | Balanced Accuracy |
| :--- | :--- | ---: | ---: | ---: |
| open-appsec / CloudGuard WAF | Critical Profile | 99.47% | 0.563% | 99.453% |
| open-appsec / CloudGuard WAF | Default Profile | 99.56% | 0.994% | 99.283% |
| F5 NGINX App Protect | Default Profile | 91.009% | 2.868% | 94.071% |
| F5 NGINX App Protect | Strict Profile | 97.907% | 25.4% | 86.254% |
| F5 BIG-IP Advanced WAF | Rapid Deployment Policy | 79.039% | 2.894% | 88.072% |
| AWS WAF | Managed + F5 Rules | 80.445% | 6.133% | 87.156% |
| AWS WAF | AWS Managed Ruleset | 79.891% | 6.046% | 86.922% |
| NGINX ModSecurity | OWASP CRS 4.20.0 | 92.257% | 18.638% | 86.81% |
| Cloudflare WAF | Managed + OWASP CRS | 63.462% | 0.06% | 81.701% |
| Microsoft Azure WAF | OWASP CRS 3.2 | 97.537% | 54.412% | 71.562% |
| Fortinet FortiAppSec | Default Configuration | 70.143% | 21.388% | 74.378% |
| Google Cloud Armor | ModSecurity (Sensitivity 2) | 91.006% | 56.999% | 67.004% |
| Barracuda WAF | Default (Modified) | 34.32% | 18.197% | 58.061% |
| Imperva Cloud WAF | Default Configuration | 11.97% | 0.009% | 55.981% |

ที่มา: https://www.openappsec.io/post/best-waf-solutions-in-2026-real-world-comparison

## 3. ปัญหาหลัก: ข้อมูลรั่ว (data leakage)

- โมเดล Gen 3 รุ่น F-canon2 (ตัวหลักใน git) เทรนด้วย `openappsec_legitimate.jsonl` (97,378 แถว) และ `openappsec_malicious.jsonl` (66,373 แถว)
- ทั้งสองไฟล์สร้างจาก **zip ชุดเดียวกับ benchmark** (`ml/prepare_external_datasets.py` ดาวน์โหลดจาก URL เดียวกัน ไฟล์ตรงกันทุก byte)
- ถ้าวัดด้วยโมเดลนี้ ผลจะสูงเกินจริง ใช้เทียบกับเจ้าอื่นไม่ได้

วิธีแก้:
1. **ใช้โมเดลรุ่นที่ไม่ใช้ OpenAppSec เลย** (CSIC + SR-BH เท่านั้น) — เทรนแล้ว (ข้อ 10.4)
2. ตรวจ overlap ด้วย SHA-256 ของ request ระหว่าง benchmark กับข้อมูลเทรนของรุ่นนี้ ต้องเป็น 0 (หรือรายงานจำนวนถ้าไม่เป็น 0)
3. ไม่ใส่ผลของ F-canon2 เดิมในตาราง (ข้อ 9)

**CRS ล้วนไม่มีปัญหานี้** เพราะไม่ได้เรียนรู้จากข้อมูล

## 4. กติกาการวัด (ตั้งก่อนเห็นผล ห้ามปรับหลังเห็นผล)

- **ห้ามปรับ threshold หรือ rule โดยดูผลจาก benchmark**
  - threshold ของ ML ใช้ค่าจาก model card (benign ผ่าน 99% บน OOF ของข้อมูลเทรน) และค่าคงที่ 0.99 ที่เลือกไว้ก่อนแล้ว
- **ห้ามเอา request ของ benchmark ไปเทรน**
- CRS ใช้ค่าเดียวกับ production: PL1, inbound anomaly threshold 5 (`modsecurity/custom-rules/00-modsecurity-override.conf`)
- ทุกแถวของเราต้องระบุว่า "วัดเองบน replica ในเครื่อง" และแนบ PDF ของเครื่องมือ
- ทุกรอบต้องรายงานจำนวน request ที่ถูกตัดเพราะ status 0

## 5. ระบบที่จะวัด

| รหัส | ระบบ | Image / Backend | หมายเหตุ |
| :--- | :--- | :--- | :--- |
| **K** | CRS 4.20.0 ค่าเริ่มต้น | `owasp/modsecurity-crs:4.20.0-nginx-202511100111` → stub | ใช้ตรวจวิธีวัด (ขั้นที่ 2) |
| **A** | CRS 3.3.8 PL1 anomaly 5 | `owasp/modsecurity-crs:nginx` → stub | **ตรงกับ production** |
| **B** | A + ML (threshold 0.99) | CRS 3.3.8 → ML harness | ค่าที่ได้คะแนน GoTestWAF ดีสุด |
| **C** | A + ML (threshold จาก model card) | CRS 3.3.8 → ML harness | ค่าตามที่โมเดลกำหนด |
| **D** | ML อย่างเดียว (threshold จาก model card) | ML harness ตรง | ดูความสามารถของโมเดลล้วน |

ML ใน B / C / D = โมเดลรุ่นไม่ใช้ OpenAppSec (`gen3_f_noopenappsec.onnx`, threshold ใน card 0.8749)
stub = `traefik/whoami` (ตอบ 200 ทุก method ทุก path)

## 6. ขั้นตอน (checklist)

### ขั้นที่ 1 — ติดตั้งและตรวจเครื่องมือ ✅
- [x] clone repo และอ่านโค้ดว่าตัดสิน "บล็อก" อย่างไร (ข้อ 2)
- [x] harness ตอบ 403 เมื่อ ML บล็อก ตรงกับที่เครื่องมือเข้าใจ — ไม่ต้องแก้
- [x] ใช้ zip ที่มีอยู่แล้ว แตกลง `results/datasets/` (ไม่ต้องโหลด 1.2 GB ใหม่)
- [x] นับจำนวน request จริง (ข้อ 2)
- [ ] ~~ทดสอบกับ stub ที่ไม่บล็อก / บล็อกทุกอย่าง~~ — ทำไม่ได้ เครื่องมือหยุดถ้า health/functional check ไม่ผ่าน ใช้ calibration กับ K แทน

### ขั้นที่ 2 — calibration ⏳ (ได้ผลบางส่วน ข้อ 10.5)
- [x] ตรวจเวอร์ชัน CRS: `owasp/modsecurity-crs:nginx` = **CRS 3.3.8** จึง pin tag `4.20.0-nginx-202511100111` ให้ K
- [ ] รัน **K** แบบ `--fast` ให้ครบ (ครั้งแรกหยุดกลางทางเพราะเครื่องช้า)
- [ ] **เกณฑ์ผ่าน:** TPR และ FPR ห่างจาก 92.257% / 18.638% ไม่เกิน ±3 จุด และ status 0 < 1%
  - ผ่าน → วิธีวัดของเราน่าเชื่อถือ ไปขั้นต่อไป
  - ไม่ผ่าน → หาสาเหตุก่อน (เวอร์ชัน CRS, paranoia level, การตัดสินบล็อก, timeout) ห้ามไปต่อ

### ขั้นที่ 3 — โมเดลที่ไม่ใช้ OpenAppSec ✅ (เหลือตรวจ overlap)
- [x] เพิ่ม `--exclude-dataset NAME` ใน `ml/train_final_gen3.py` (commit `c1d3d58e`) ทดสอบด้วยข้อมูลจำลองแล้ว
- [x] notebook: `FINAL_FEATURE_SETS = ["F"]`, `FINAL_EXCLUDE_DATASETS = ["OpenAppSec"]`, `EXPERIMENT_MODE = "none"`
- [x] เทรนบน Colab แล้ว: `gen3-final-f-noopenappsec-20261002-153004` (ข้อ 10.4)
- [ ] ดาวน์โหลด ONNX มาไว้ใน repo ของเครื่องที่จะรัน (ข้อ 11 ขั้น 3)
- [ ] ตรวจ overlap ด้วย SHA-256 ระหว่าง benchmark กับข้อมูลเทรนของรุ่นนี้ (CSIC + SR-BH)

### ขั้นที่ 4 — วัดจริง
- [ ] รอบทดลอง: A, B, C, D แบบ `--fast`
- [ ] จับเวลารอบ `--fast` แล้วประมาณเวลารอบเต็ม
- [ ] รอบจริง: K, A, B, C, D แบบเต็ม (1.1 ล้าน request ต่อระบบ) — ตัวเลขที่ใช้ในตารางมาจากรอบนี้
- [ ] เก็บ PDF, DuckDB, `summary-*.txt` และ log ของ harness ทุกรอบไว้ (ไม่ขึ้น git)

### ขั้นที่ 5 — วิเคราะห์
- [ ] คำนวณ TPR, FPR, Balanced Accuracy ของทุกระบบ (`summarize_db.py`)
- [ ] แยกตามประเภทการโจมตี (ชื่อไฟล์ malicious = ประเภท) เทียบ A กับ B ว่า ML เติมตรงไหน
- [ ] สุ่มดู request ปกติที่โดนบล็อก (FP) ของ B และ D อย่างละ 50 ตัว จัดกลุ่มสาเหตุ
- [ ] เทียบกับผลของ GoTestWAF ว่าทิศทางตรงกันไหม

### ขั้นที่ 6 — สรุปผล
- [ ] `ml/security_test/RESULTS_OPENAPPSEC_BENCHMARK.md`: ตารางรวม 14 แถวที่เผยแพร่ + K, A–D ของเรา พร้อมคอลัมน์ "ที่มา"
- [ ] อัปเดตคู่มือ WAF Gen 3 และสไลด์
- [ ] commit และ push เฉพาะ branch `trainmodelgen3` (รายงานและสคริปต์ ไม่รวม dataset)

## 7. ข้อจำกัดที่ต้องเขียนไว้ในรายงาน

1. เจ้าอื่นวัดบนบริการจริงบน AWS ส่วนเราวัดบน replica ในเครื่อง — ผลขั้นที่ 2 บอกว่าต่างกันแค่ไหน
2. ผลที่เผยแพร่ทำโดย Check Point ซึ่งเป็นเจ้าของ open-appsec
3. dataset สาธารณะอาจไม่ใช่ชุดเดียวกับที่ใช้วัดปี 2026 ทุก request (malicious 73,924 กับ 74,284)
4. ML ในตารางเป็นรุ่นที่ไม่ใช้ OpenAppSec — ความสามารถจริงของรุ่นที่ใช้งาน (F-canon2) บนข้อมูลชุดนี้วัดอย่างยุติธรรมไม่ได้
5. benchmark นี้วัดเฉพาะ request เดี่ยว ไม่วัด bot, DDoS, rate limit และ API protocol
6. request ที่ timeout (status 0) ถูกเครื่องมือตัดออก — รายงานจำนวนทุกรอบ
7. nginx ของ replica ตอบ 400 กับ request ปกติบางตัว (เช่น parse body ไม่ได้) เครื่องมือนับว่า "ไม่บล็อก"
8. production ใช้ CRS 3.3.8 ส่วนแถวที่เผยแพร่ใช้ CRS 4.20.0 — ระบบ A เทียบกับแถว ModSecurity ตรงๆ ไม่ได้ ต้องดูคู่กับ K

## 8. ทรัพยากร

| รายการ | ค่า |
| :--- | :--- |
| ค่าใช้จ่าย | 0 บาท (Docker, Colab ฟรี, เครื่องตัวเอง) |
| ดิสก์ | dataset แตกแล้ว ~7 GB + zip 1.2 GB + DB/log ~2–5 GB ต่อรอบเต็ม · เผื่อว่าง ≥ 20 GB |
| RAM ที่ benchmark ใช้จริง | tool ~250 MB, CRS ~70–90 MB/ตัว, stub ~10 MB, ML harness ~250–300 MB/ตัว |
| RAM ที่แนะนำของเครื่อง | ≥ 16 GB (เครื่องเดิม 7.8 GB เหลือว่าง 0.6 GB ระหว่างรัน → ช้าและ timeout) |
| CPU ที่แนะนำ | ≥ 8 core |
| เวลา | ดูข้อ 10.6 |

## 9. การตัดสินใจ (2 ต.ค. 2569)

- [x] **รอบเต็ม** สำหรับทุกระบบที่ขึ้นตาราง (ผลที่เผยแพร่วัดจาก dataset เต็ม) — รัน `--fast` ก่อนเพื่อจับเวลาและตรวจความถูกต้อง
- [x] **เทรนโมเดลรุ่นที่ไม่ใช้ OpenAppSec** (ขั้นที่ 3) — จำเป็นสำหรับการเทียบที่ยุติธรรม
- [x] **ไม่ใส่ผลของ F-canon2 เดิมในตาราง** — เขียนเหตุผลไว้ในข้อจำกัดข้อ 4 เท่านั้น กันตัวเลขที่สูงเกินจริงถูกนำไปใช้
- [x] **ย้ายไปรันบนเครื่องที่แรงกว่า** — เครื่องเดิมช้าและเริ่มมี timeout (ข้อ 10.6)

## 10. บันทึกความคืบหน้า (สิ่งที่ทำมาแล้ว)

### 10.1 ก่อนเริ่มแผนนี้ (เพื่อเข้าใจที่มา)
- ทดสอบด้วย GoTestWAF บน replica ในเครื่อง (CRS 3.3.8 ตามที่รู้ทีหลัง): CRS anomaly 5 ได้ D 63.3, CRS + ML (F-canon2) threshold 0.99 ได้ D 64.9 ดีที่สุด
- รายงาน GoTestWAF บน production (C+ 78.2) สูงเกินจริงเพราะ request 292 ตัวได้ 405 และถูกตัดออก
- ค้นหา benchmark มาตรฐาน: SecureIQLab (AMTSO) รันซ้ำไม่ได้ · open-appsec รันซ้ำได้ → เลือกเป็นตัวเทียบหลัก · CrowdStrike ไม่มีผลิตภัณฑ์ WAF

### 10.2 โค้ดที่เพิ่ม (ขึ้น git แล้ว)
| ไฟล์ | ใช้ทำอะไร |
| :--- | :--- |
| `ml/security_test/openappsec/run_benchmark.sh` | ตั้ง container ระบบ K/A/B/C/D + stub + ML harness แล้วรันเครื่องมือ และสรุปผล |
| `ml/security_test/openappsec/Dockerfile.harness` | image ของ ML harness (Python 3.12 + `ml/requirements-serve.txt`) |
| `ml/security_test/openappsec/summarize_db.py` | อ่าน DuckDB ของเครื่องมือ → TPR/FPR/Balanced + จำนวน status 0 ที่ถูกตัด |
| `ml/train_final_gen3.py --exclude-dataset` | เทรนโดยตัด dataset ที่ระบุ |
| `ml/waf_gen3_colab.ipynb` | ตั้งค่าเทรนรุ่นไม่ใช้ OpenAppSec |

### 10.3 ข้อค้นพบสำคัญ
- **production ใช้ CRS 3.3.8** (`owasp/modsecurity-crs:nginx`) ไม่ใช่ 4.x — ผล GoTestWAF ของ CRS replica ก่อนหน้านี้ทั้งหมดเป็น 3.3.8
- เครื่องมือ **ตัด status 0 (timeout) ออกจากการคำนวณ** — ต้องรายงานทุกรอบ
- CRS บล็อก traffic ปกติจริงในชุดนี้ด้วย rule เช่น 932270 (RCE Unix shell), 920420 (content type), 932250
- nginx ตอบ 400 กับ request ปกติบางตัว (rule 200002 "Failed to parse request body" และ nginx เอง)

### 10.4 โมเดลรุ่นไม่ใช้ OpenAppSec (Colab, 2 ต.ค. 2569)
| รายการ | ค่า |
| :--- | :--- |
| โฟลเดอร์บน Drive | `waf_ml/models/gen3-final-f-noopenappsec-20261002-153004/` |
| ข้อมูล | ตัด OpenAppSec 163,751 แถว เหลือ 133,977 แถว (CSIC 2010 + SR-BH 2020) |
| Threshold (card) | 0.8749 |
| Scenario | ปกติ 37/37 · โจมตี 23/26 (พลาด probe หน้า admin 3 ข้อเหมือนเดิม) |
| OOF รวม | Precision 99.81% / Recall 92.03% / F1 95.76% |
| ONNX | parity 3.7×10⁻⁷ · latency p50 0.30 ms |

### 10.5 ผล calibration บางส่วน (⚠️ ไม่ครบ ห้ามใช้เป็นผลสรุป)
รอบ `--fast` 16 workers บนเครื่องเดิม หยุดหลัง ~7 นาที — malicious ครบตามตัวอย่าง 15% (11,087 ตัว) แต่ legit ทำได้แค่ 12,735 จาก ~156,000 (เว็บเรียงตามตัวอักษร 40 กว่าเว็บแรก จึงเอียง)

| ระบบ | TPR (malicious ครบ) | FPR (legit ~8% ของตัวอย่าง) | status 0 ที่ถูกตัด (legit) |
| :--- | ---: | ---: | ---: |
| K CRS 4.20.0 | **90.142%** (เผยแพร่ 92.257% → ต่าง −2.1 อยู่ในเกณฑ์ ±3) | 36.243% (เผยแพร่ 18.638% — ข้อมูลยังไม่พอสรุป) | 418 / 12,735 (3.3%) |
| A CRS 3.3.8 PL1 a5 | 86.235% | 17.990% | 417 / 12,735 (3.3%) |

สิ่งที่บอกได้แล้ว: TPR ของ K ใกล้ค่าที่เผยแพร่ แปลว่าการส่ง request และการตัดสินบล็อกของเราน่าจะถูก
สิ่งที่ยังบอกไม่ได้: FPR (ต้องรันให้ครบทุกเว็บ) และ status 0 ที่ 3.3% สูงเกินเกณฑ์ < 1% (น่าจะเพราะเครื่องช้า)

### 10.6 เรื่องเวลาและเครื่อง
| การตั้งค่า | ความเร็ววัดจริงบนเครื่องเดิม | เวลาโดยประมาณ (K + A) |
| :--- | :--- | :--- |
| 4 workers (ค่าเริ่มต้น) | 200–750 request/นาที/ระบบ | `--fast` 2.5–5 ชม. |
| 16 workers | 2,000–2,800 request/นาที/ระบบ | `--fast` ~1–1.25 ชม. · เต็ม ~7–9 ชม. |

- คอขวดอยู่ที่ตัวเครื่องมือ (CPU ของ CRS 0–5%) และ RAM ที่ว่างเหลือน้อยบนเครื่องเดิม
- เครื่องมือส่ง request ทีละระบบ จึงใช้เวลาแปรตามจำนวนระบบที่ใส่ในรอบเดียว

## 11. วิธีรันบนเครื่องใหม่

### ขั้นที่ 1 — เตรียมเครื่อง
- Docker Desktop (Linux containers) หรือ Docker Engine บน Linux · ถ้าเป็น Windows ให้รันใน WSL2 และเปิด WSL Integration ให้ distro ที่ใช้
- ตั้ง RAM ให้ Docker/WSL อย่างน้อย 8 GB (Docker Desktop: Settings → Resources หรือ `.wslconfig`)
- ดิสก์ว่าง ≥ 20 GB

### ขั้นที่ 2 — โหลดโค้ด
```bash
git clone -b trainmodelgen3 https://github.com/jakkaret/waf_project.git
cd waf_project
```

### ขั้นที่ 3 — วางโมเดลรุ่นไม่ใช้ OpenAppSec
ดาวน์โหลด `gen3_f_model.onnx` จาก Drive `waf_ml/models/gen3-final-f-noopenappsec-20261002-153004/`
แล้ววางที่ **`ml/models/gen3/gen3_f_noopenappsec.onnx`** (ไฟล์นี้ไม่ขึ้น git)

### ขั้นที่ 4 — (ไม่บังคับ) ใช้ dataset ที่มีอยู่แล้ว
ถ้ามี `legitimate.zip` / `malicious.zip` แล้ว ให้แตกไว้ที่ `~/waf-bench/results/datasets/` จะได้ไม่ต้องโหลดใหม่
(ไม่มี: เครื่องมือโหลดเองในรอบแรก ~1.2 GB และแตกเป็น ~7 GB)

### ขั้นที่ 5 — calibration (K + A แบบ fast)
```bash
bash ml/security_test/openappsec/run_benchmark.sh --systems K,A --fast --workers 32
```
- ตรวจผลตามเกณฑ์ขั้นที่ 2 (TPR/FPR ของ K ห่างจาก 92.257% / 18.638% ไม่เกิน ±3 จุด และ status 0 < 1%)
- ถ้า status 0 สูง ให้ลด `--workers` แล้วรันใหม่

### ขั้นที่ 6 — ระบบที่มี ML (fast ก่อน)
```bash
bash ml/security_test/openappsec/run_benchmark.sh --systems A,B,C,D --fast --workers 32
```

### ขั้นที่ 7 — รอบเต็ม (ตัวเลขที่ใช้จริง)
```bash
bash ml/security_test/openappsec/run_benchmark.sh --systems K,A,B,C,D --workers 32
```
หรือแยกรันทีละ 1–2 ระบบถ้าอยากให้แต่ละรอบสั้นลง (แต่ละรอบใช้ `--fresh-run` จะลบ DB ของรอบก่อน → **เก็บ PDF และ `summary-*.txt` ก่อนรันรอบถัดไป**)

### ผลที่ได้แต่ละรอบ (ใน `~/waf-bench/results/`)
- `waf-comparison-report.pdf` — รายงานของเครื่องมือ
- `summary-<เวลา>.txt` — TPR / FPR / Balanced + จำนวน status 0
- `db/waf_comparison.duckdb` — ผลราย request (ใช้ในขั้นที่ 5)
- `harness-logs/oa-ml-*.jsonl` — คะแนน ML ราย request (ระบบ B/C/D)

ส่งไฟล์ PDF และ `summary-*.txt` มาให้ Claude วิเคราะห์ต่อได้

## 12. สิ่งที่จะทำต่อ (เรียงตามลำดับ)

1. รัน calibration K + A แบบ fast บนเครื่องใหม่ให้ครบ → ตัดสินว่าผ่านเกณฑ์หรือไม่
2. ตรวจ overlap SHA-256 ระหว่าง benchmark กับข้อมูลเทรนของรุ่นไม่ใช้ OpenAppSec
3. รัน A, B, C, D แบบ fast → ดูแนวโน้ม และประเมินเวลารอบเต็ม
4. รอบเต็ม K, A, B, C, D
5. วิเคราะห์ (ขั้นที่ 5) และเขียน `RESULTS_OPENAPPSEC_BENCHMARK.md`
6. อัปเดตคู่มือ WAF Gen 3 และสไลด์
7. (ทางเลือก) วัด CRS 4.20 + ML เพิ่ม เพื่อดูว่าการอัปเกรด CRS ของ production จาก 3.3.8 เป็น 4.x ให้ผลอย่างไร

## 13. ผลลัพธ์ที่จะได้

- PDF ของเครื่องมือ open-appsec สำหรับระบบ K, A–D
- ตารางเทียบกับ 14 ผลิตภัณฑ์ที่ระบุที่มาทุกแถว
- คำตอบที่มีตัวเลขรองรับว่า ML ช่วย CRS ได้เท่าไหร่บนข้อมูลจริงขนาดใหญ่ และ FP เพิ่มเท่าไหร่
