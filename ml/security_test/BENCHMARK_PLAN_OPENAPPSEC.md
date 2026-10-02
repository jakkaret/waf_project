# แผนเทียบระบบ WAF ของเรากับผลิตภัณฑ์อื่นด้วย open-appsec WAF Comparison

> สถานะ: **แผน — ยังไม่ได้รัน** · จัดทำ 2 ต.ค. 2569 · branch `trainmodelgen3`
> ทุกการทดสอบรันบนเครื่อง local (Docker + `127.0.0.1`) ไม่แตะ VPS production และไม่มีค่าใช้จ่าย

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
| Repo | https://github.com/openappsec/waf-comparison-project |
| Docker image | `ghcr.io/openappsec/waf-comparison-project:latest` |
| Legitimate dataset | `https://downloads.openappsec.io/waf-comparison-project/legitimate.zip` · 1,203,983,791 bytes · last-modified 1 ธ.ค. 2024 |
| Malicious dataset | `https://downloads.openappsec.io/waf-comparison-project/malicious.zip` · 452,537 bytes · last-modified 17 ก.ค. 2023 |
| ไฟล์ที่เรามีอยู่แล้ว | `~/.cache/wafprobe/legitimate.zip` (sha256 `58faee18…d778`), `malicious.zip` (sha256 `131314e5…b7b2b`) — ขนาดตรงกับบนเซิร์ฟเวอร์ |
| ตัวเลือกของเครื่องมือ | `--waf-name`, `--waf-url` (ใส่หลายคู่ได้), `--max-workers`, `--fast` (สุ่ม 15%), `--fresh-run` |
| ผลลัพธ์ | `results/waf-comparison-report.pdf` + ฐานข้อมูล DuckDB |

ความไม่ตรงกันที่ต้องบันทึกในรายงาน:
- README: 73,924 malicious จาก "185 เว็บ 12 หมวด" · บทความปี 2026: 74,284 malicious จาก "692 เว็บ 14 หมวด"
- แปลว่าปี 2026 อาจใช้ชุดที่ต่างจากไฟล์สาธารณะเล็กน้อย ตัวเลขของเราจึงเทียบได้ใกล้เคียง ไม่ใช่ตรงทุก request

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

- โมเดล Gen 3 รุ่น F-canon2 เทรนด้วย `openappsec_legitimate.jsonl` (97,378 แถว) และ `openappsec_malicious.jsonl` (66,373 แถว)
- ทั้งสองไฟล์สร้างจาก **zip ชุดเดียวกับ benchmark** (`ml/prepare_external_datasets.py`)
- ถ้าวัดด้วยโมเดลนี้ ผลจะสูงเกินจริง ใช้เทียบกับเจ้าอื่นไม่ได้

วิธีแก้:
1. **เทรนโมเดลรุ่นที่ไม่ใช้ OpenAppSec เลย** (CSIC + SR-BH เท่านั้น) และใช้รุ่นนี้รุ่นเดียวในตารางเทียบ
2. ตรวจ overlap ด้วย SHA-256 ของ request ระหว่าง benchmark กับข้อมูลเทรนของรุ่นใหม่ ต้องเป็น 0 (หรือรายงานจำนวนถ้าไม่เป็น 0)
3. ผลของ F-canon2 เดิมรายงานแยกได้ แต่ต้องติดป้าย **"เคยเห็นข้อมูลชุดนี้ตอนเทรน — อ้างอิงเท่านั้น"**

**CRS ล้วนไม่มีปัญหานี้** เพราะไม่ได้เรียนรู้จากข้อมูล

## 4. กติกาการวัด (ตั้งก่อนเห็นผล ห้ามปรับหลังเห็นผล)

- **ห้ามปรับ threshold หรือ rule โดยดูผลจาก benchmark**
  - threshold ของ ML ใช้ค่าจาก model card (benign ผ่าน 99% บน OOF ของข้อมูลเทรน) และค่าคงที่ 0.99 ที่เลือกไว้ก่อนแล้ว
- **ห้ามเอา request ของ benchmark ไปเทรน**
- CRS ใช้ค่าเดียวกับ production: PL1, inbound anomaly threshold 5 (`modsecurity/custom-rules/00-modsecurity-override.conf`)
- ทุกแถวของเราต้องระบุว่า "วัดเองบน replica ในเครื่อง" และแนบ PDF ของเครื่องมือ

## 5. ระบบที่จะวัด

| รหัส | ระบบ | Backend | หมายเหตุ |
| :--- | :--- | :--- | :--- |
| **A** | CRS PL1 anomaly 5 | stub ตอบ 200 ทุก request | ตรงกับ production |
| **B** | CRS + ML (threshold 0.99) | ML harness | ค่าที่ได้คะแนน GoTestWAF ดีสุด |
| **C** | CRS + ML (threshold จาก model card) | ML harness | ค่าตามที่โมเดลกำหนด |
| **D** | ML อย่างเดียว (threshold จาก model card) | ML harness ตรง ไม่มี CRS | ดูความสามารถของโมเดลล้วน |
| **K** | CRS ตามแถว "OWASP CRS 4.20.0" | stub | ใช้ตรวจวิธีวัด (ขั้นที่ 2) |

ML ใน B / C / D ต้องเป็นโมเดลรุ่นที่ไม่ใช้ OpenAppSec (ขั้นที่ 3)

## 6. ขั้นตอน

### ขั้นที่ 1 — ติดตั้งและตรวจเครื่องมือ (~ครึ่งวัน)
- [ ] clone repo และอ่านโค้ดว่า **ตัดสิน "บล็อก" อย่างไร** (status code / block page / connection error)
- [ ] ปรับ harness (`ml/security_test/waf_test_harness.py`) ให้ตอบแบบที่เครื่องมือเข้าใจว่าบล็อก
- [ ] วาง zip ที่มีอยู่แล้วลง `results/datasets/` เพื่อไม่ต้องโหลด 1.2 GB ใหม่ (หรือให้เครื่องมือโหลดเองแล้วเทียบ sha256)
- [ ] นับจำนวน request จริงหลังแตกไฟล์ บันทึกเทียบกับ 73,924 / 74,284
- [ ] **ทดสอบความถูกต้องของเครื่องมือกับเป้าที่รู้คำตอบ:**
  - stub ที่ไม่บล็อกอะไรเลย ต้องได้ TPR ≈ 0%, FPR = 0%
  - stub ที่บล็อกทุกอย่าง ต้องได้ TPR = 100%, FPR = 100%

### ขั้นที่ 2 — ตรวจว่าวิธีวัดของเราตรงกับของเขา (calibration, ~1–2 ชม.)
- [ ] ตรวจเวอร์ชัน CRS ใน `owasp/modsecurity-crs:nginx` ถ้าไม่ใช่ 4.20.0 ให้ pin image tag ที่ตรง
- [ ] รันระบบ **K** แบบ `--fast`
- [ ] **เกณฑ์ผ่าน:** TPR และ FPR ห่างจาก 92.257% / 18.638% ไม่เกิน ±3 จุด
  - ผ่าน → วิธีวัดของเราน่าเชื่อถือ ไปขั้นต่อไป
  - ไม่ผ่าน → หาสาเหตุก่อน (เวอร์ชัน CRS, paranoia level, การตัดสินบล็อก, วิธีส่ง request) ห้ามไปต่อ

### ขั้นที่ 3 — เทรนโมเดลที่ไม่ใช้ OpenAppSec (Colab ฟรี ~1 ชม.)
- [ ] เพิ่ม option `--exclude-dataset OpenAppSec` ใน `ml/train_final_gen3.py` และเพิ่มเทสต์
- [ ] notebook: ตั้ง `FINAL_FEATURE_SETS = ["F"]` และใส่ flag ใหม่
- [ ] ได้ `gen3_f_model.onnx` รุ่น "no-openappsec" พร้อม model card (threshold, sources ต้องไม่มี OpenAppSec)
- [ ] ตรวจ overlap ด้วย SHA-256 กับ benchmark (ข้อ 3)

### ขั้นที่ 4 — วัดจริง
- [ ] รอบทดลอง: A, B, C, D แบบ `--fast` (สุ่ม 15%) ทีละระบบหรือ 2 ระบบพร้อมกัน (RAM เครื่องว่าง ~2.6 GB)
- [ ] จับเวลารอบ `--fast` แล้วประมาณเวลารอบเต็ม
- [ ] รอบจริง: A, B, C, D แบบเต็ม (1.1 ล้าน request) — ตัวเลขที่ใช้ในตารางมาจากรอบนี้
- [ ] เก็บ PDF, DuckDB และ log ของ harness ทุกรอบไว้ที่ `ml/security_test/reports/openappsec-benchmark/` (ไม่ขึ้น git)

### ขั้นที่ 5 — วิเคราะห์
- [ ] คำนวณ TPR, FPR, Balanced Accuracy ของทุกระบบ
- [ ] แยกตามประเภทการโจมตี (ถ้า malicious dataset มีป้ายประเภท) เทียบ A กับ B ว่า ML เติมตรงไหน
- [ ] สุ่มดู request ปกติที่โดนบล็อก (FP) ของ B และ D อย่างละ 50 ตัว จัดกลุ่มสาเหตุ
- [ ] เทียบกับผลของ GoTestWAF ว่าทิศทางตรงกันไหม

### ขั้นที่ 6 — สรุปผล
- [ ] `ml/security_test/RESULTS_OPENAPPSEC_BENCHMARK.md`: ตารางรวม 14 แถวที่เผยแพร่ + A–D ของเรา พร้อมคอลัมน์ "ที่มา"
- [ ] อัปเดตคู่มือ WAF Gen 3 และสไลด์
- [ ] commit และ push เฉพาะ branch `trainmodelgen3` (รายงานและสคริปต์ ไม่รวม dataset)

## 7. ข้อจำกัดที่ต้องเขียนไว้ในรายงาน

1. เจ้าอื่นวัดบนบริการจริงบน AWS ส่วนเราวัดบน replica ในเครื่อง — ผลขั้นที่ 2 บอกว่าต่างกันแค่ไหน
2. ผลที่เผยแพร่ทำโดย Check Point ซึ่งเป็นเจ้าของ open-appsec
3. dataset สาธารณะอาจไม่ใช่ชุดเดียวกับที่ใช้วัดปี 2026 ทุก request (73,924 กับ 74,284)
4. ML ในตารางเป็นรุ่นที่ไม่ใช้ OpenAppSec — ความสามารถจริงของรุ่นที่ใช้งาน (F-canon2) บนข้อมูลชุดนี้วัดอย่างยุติธรรมไม่ได้
5. benchmark นี้วัดเฉพาะ request เดี่ยว ไม่วัด bot, DDoS, rate limit และ API protocol

## 8. ทรัพยากร

| รายการ | ประมาณ |
| :--- | :--- |
| ค่าใช้จ่าย | 0 บาท (Docker, Colab ฟรี, เครื่องตัวเอง) |
| ดิสก์เพิ่ม | ~3–5 GB (dataset มีแล้ว 1.2 GB) |
| RAM | CRS ~100 MB/ตัว, ML harness ~250 MB/ตัว, เครื่องมือ + DuckDB |
| เวลา | ขั้น 1–3 ~1 วัน · รอบเต็มประเมินหลังจับเวลารอบ `--fast` |

## 9. การตัดสินใจ (2 ต.ค. 2569)

- [x] **รอบเต็ม** สำหรับทุกระบบที่ขึ้นตาราง (ผลที่เผยแพร่วัดจาก dataset เต็ม) — รัน `--fast` ก่อนเพื่อจับเวลาและตรวจความถูกต้อง
- [x] **เทรนโมเดลรุ่นที่ไม่ใช้ OpenAppSec** (ขั้นที่ 3) — จำเป็นสำหรับการเทียบที่ยุติธรรม
- [x] **ไม่ใส่ผลของ F-canon2 เดิมในตาราง** — เขียนเหตุผลไว้ในข้อจำกัดข้อ 4 เท่านั้น กันตัวเลขที่สูงเกินจริงถูกนำไปใช้

## 10. ผลลัพธ์ที่จะได้

- PDF ของเครื่องมือ open-appsec สำหรับระบบ A–D
- ตารางเทียบกับ 14 ผลิตภัณฑ์ที่ระบุที่มาทุกแถว
- คำตอบที่มีตัวเลขรองรับว่า ML ช่วย CRS ได้เท่าไหร่บนข้อมูลจริงขนาดใหญ่ และ FP เพิ่มเท่าไหร่
