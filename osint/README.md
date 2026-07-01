# 🔍 OSINT Intelligence Portal — Law Enforcement Edition

A full-stack Streamlit application that guides investigators through structured OSINT research using 1,167 tools from osintframework.com.

---

## 📁 Files

| File | Description |
|---|---|
| `app.py` | Main Streamlit application |
| `osint_tools.json` | 1,167 OSINT tools parsed from osintframework.com GitHub repo |

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install streamlit pandas
```

### 2. Place both files in the same folder
```
osint_portal/
  ├── app.py
  └── osint_tools.json
```

### 3. Run the app
```bash
streamlit run app.py
```

Open your browser to `http://localhost:8501`

---

## 🔄 User Flow

```
Step 1: Case Setup
  → Enter case number, investigator, agency, subject identifiers

Step 2: Select Data Types
  → Choose which data you have (email, phone, username, IP, etc.)
  → Smart auto-detection from Step 1 inputs

Step 3: Find Tools
  → Browse 1,167 OSINT tools filtered to your selected categories
  → Filter by: free/freemium/paid, passive OpSec, no-registration
  → Full-text search across all tool descriptions
  → Select tools you plan to use

Step 4: Enter Findings
  → For each selected tool, open its link and run your queries
  → Paste results back into the portal text boxes

Step 5: Generate Report
  → Full intelligence report with subject profile + all findings
  → Download as .txt or .json
  → Classification levels (UNCLASSIFIED through SECRET)
```

---

## 🛡️ Features

- **33 OSINT categories** including Username, Email, Phone, IP, Social Networks, Dark Web, Blockchain, Public Records, and more
- **1,167 tools** with full metadata: pricing, OpSec level, input/output, registration requirements
- **Smart filters**: free only, no registration, passive OpSec
- **Sub-category navigation** within each major category
- **Full-text search** across tool names, descriptions, and inputs
- **Auto-suggest** data types based on identifiers entered in case setup
- **Report export** as plain text or JSON for agency records
- **Dark professional UI** designed for investigative workflows

---

## ⚠️ Legal Notice

This portal is intended for use by authorized law enforcement personnel only.
All OSINT activity must comply with applicable laws and agency policy.
Data collected via OSINT tools must be independently corroborated before use in legal proceedings.
