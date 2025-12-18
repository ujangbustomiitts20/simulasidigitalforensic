# CHAIN OF CUSTODY TEMPLATE
## Digital Forensic Investigation

---

## CASE INFORMATION

| Field | Value |
|-------|-------|
| **Case ID** | [CASE_YYYYMMDD_XXX] |
| **Case Name** | [Nama Kasus] |
| **Investigation Type** | [Data Breach / Malware / Unauthorized Access / etc.] |
| **Date Opened** | [YYYY-MM-DD] |
| **Lead Investigator** | [Nama Investigator] |
| **Organization** | [Nama Organisasi] |

---

## EVIDENCE ITEM DETAILS

### Evidence Item #1

| Property | Value |
|----------|-------|
| **Evidence ID** | EVD-001 |
| **Description** | [Deskripsi detail evidence] |
| **Type** | [Hard Drive / USB Drive / Server / Mobile Device / Log File] |
| **Make/Model** | [Manufacturer dan model jika applicable] |
| **Serial Number** | [Serial number perangkat] |
| **Capacity** | [Kapasitas penyimpanan] |
| **Condition** | [Physical condition saat diterima] |

#### Hash Values (Evidence Integrity)

| Algorithm | Hash Value |
|-----------|------------|
| **MD5** | [32-character hash] |
| **SHA-1** | [40-character hash] |
| **SHA-256** | [64-character hash] |

#### Initial Collection

| Field | Value |
|-------|-------|
| **Collected By** | [Nama] |
| **Date/Time** | [YYYY-MM-DD HH:MM:SS TZ] |
| **Location** | [Lokasi pengambilan] |
| **Collection Method** | [Imaging tool, procedure used] |
| **Witness Present** | [Nama saksi jika ada] |

---

## CHAIN OF CUSTODY LOG

### Transfer Record

| # | Date/Time | Released By | Received By | Purpose | Location | Condition | Signatures |
|---|-----------|-------------|-------------|---------|----------|-----------|------------|
| 1 | [YYYY-MM-DD HH:MM] | [Nama] | [Nama] | Initial Collection | [Lokasi] | [Condition] | _______ / _______ |
| 2 | [YYYY-MM-DD HH:MM] | [Nama] | [Nama] | Forensic Analysis | [Lab Location] | [Condition] | _______ / _______ |
| 3 | [YYYY-MM-DD HH:MM] | [Nama] | [Nama] | [Purpose] | [Location] | [Condition] | _______ / _______ |

---

## STORAGE INFORMATION

| Field | Value |
|-------|-------|
| **Storage Location** | [Alamat lengkap fasilitas penyimpanan] |
| **Storage Type** | [Evidence Locker / Safe / Secure Room] |
| **Access Control** | [Key / Keycard / Biometric / Combination] |
| **Temperature Controlled** | [Yes / No] |
| **Humidity Controlled** | [Yes / No] |

### Storage Access Log

| Date/Time | Person | Purpose | Duration |
|-----------|--------|---------|----------|
| [YYYY-MM-DD HH:MM] | [Nama] | [Purpose] | [Duration] |

---

## ANALYSIS RECORD

### Forensic Examination

| Field | Value |
|-------|-------|
| **Examiner** | [Nama dan credentials] |
| **Examination Date** | [YYYY-MM-DD] |
| **Tools Used** | [List forensic tools dengan versi] |
| **Workstation ID** | [ID workstation yang digunakan] |

### Working Copy Information

| Field | Value |
|-------|-------|
| **Working Copy Created** | [Yes / No] |
| **Working Copy ID** | [ID working copy] |
| **Working Copy Hash** | [SHA-256 hash] |
| **Hash Verification** | [Verified - Match / Mismatch] |

---

## EVIDENCE HANDLING NOTES

### Special Handling Requirements

- [ ] Requires write-blocker
- [ ] Requires anti-static handling
- [ ] Requires specific software/hardware
- [ ] Requires encryption key
- [ ] Contains sensitive/classified data
- [ ] Subject to legal hold

### Observations and Notes

```
[Catatan tambahan mengenai kondisi evidence, anomali yang ditemukan, 
atau informasi penting lainnya]

Date: [YYYY-MM-DD]
Observer: [Nama]
Notes:
_____________________________________________________________________
_____________________________________________________________________
_____________________________________________________________________
```

---

## INCIDENT TIMELINE REFERENCE

| Date/Time | Event | Relevance to Evidence |
|-----------|-------|----------------------|
| [YYYY-MM-DD HH:MM] | [Event description] | [How evidence relates] |

---

## LEGAL AUTHORIZATION

### Authorization Documents

| Document Type | Document Number | Issued By | Date |
|---------------|-----------------|-----------|------|
| Search Warrant | [Number] | [Authority] | [Date] |
| Consent Form | [Reference] | [Subject] | [Date] |
| Court Order | [Number] | [Court] | [Date] |

### Legal Notes

```
[Referensi ke dokumen legal yang mengotorisasi pengumpulan 
dan pemeriksaan evidence]
```

---

## VERIFICATION AND SIGNATURES

### Chain of Custody Officer

| Field | Value |
|-------|-------|
| **Name** | ________________________________ |
| **Title** | ________________________________ |
| **Organization** | ________________________________ |
| **Signature** | ________________________________ |
| **Date** | ________________________________ |

### Lead Investigator

| Field | Value |
|-------|-------|
| **Name** | ________________________________ |
| **Title** | ________________________________ |
| **Badge/ID Number** | ________________________________ |
| **Signature** | ________________________________ |
| **Date** | ________________________________ |

### Witness (if applicable)

| Field | Value |
|-------|-------|
| **Name** | ________________________________ |
| **Title/Affiliation** | ________________________________ |
| **Signature** | ________________________________ |
| **Date** | ________________________________ |

---

## APPENDICES

### Appendix A: Photographic Evidence

[Attach photos of evidence at time of collection showing:
- Overall condition
- Serial numbers
- Any damage or anomalies
- Evidence tags/labels]

### Appendix B: Tool Verification

| Tool | Version | License | Verification Hash |
|------|---------|---------|-------------------|
| [Tool name] | [Version] | [License #] | [Hash] |

### Appendix C: Forensic Image Details

| Property | Value |
|----------|-------|
| **Image Format** | [E01 / DD / AFF] |
| **Image File(s)** | [Filename(s)] |
| **Total Size** | [Size in bytes] |
| **Segment Size** | [If applicable] |
| **Compression** | [Type if used] |
| **Encryption** | [Type if used] |

---

## DOCUMENT CONTROL

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [YYYY-MM-DD] | [Name] | Initial creation |
| | | | |

---

**CONFIDENTIALITY NOTICE**

This document contains confidential information related to a forensic investigation. 
Unauthorized disclosure, copying, or distribution is strictly prohibited. 
This document may be subject to legal privilege and/or work product protection.

---

*Document ID: COC-[CASE_ID]-[EVIDENCE_ID]*
*Generated: [Timestamp]*
*Classification: [CONFIDENTIAL / RESTRICTED / etc.]*
