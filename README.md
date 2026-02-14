# 🛡️ Agentic SOC Analyst

**AI-Powered Threat Hunting for Microsoft Sentinel**

------------------------------------------------------------------------

## 📌 Overview

**Agentic SOC Analyst** is a web-based AI-powered threat hunting
assistant designed to support SOC teams in detecting suspicious or
malicious activity within:

-   Microsoft Defender for Endpoint (MDE)
-   Azure Active Directory (AAD / Entra ID)
-   Azure Activity Logs
-   Microsoft Sentinel (Log Analytics)

The system combines:

-   Structured guardrails
-   Controlled KQL generation
-   Log Analytics querying
-   LLM-driven threat analysis
-   Professional investigation reporting
-   Automated mitigation playbook generation (PDF)

   ![Agentic_AI UI](https://github.com/cfazuero1/agentic-ai/blob/main/agentic_ai.png)

------------------------------------------------------------------------

## 🧠 Architecture

### System Message & User Prompt Flow

The system operates using a structured agent design:

1.  **System Message**
    -   Defines the AI's role as a threat hunting assistant.
    -   Restricts scope to security investigation.
    -   Enforces reporting format.
2.  **User Message**
    -   Contains the SOC analyst's investigation request.
    -   Provides log analysis instructions.
    -   Defines structured output expectations.
  
![Agentic_AI Architecture](https://github.com/cfazuero1/agentic-ai/blob/main/AI-driven%20security%20monitoring%20system.png)

------------------------------------------------------------------------

### 🔐 Agentic Guardrails Architecture

The platform enforces strict guardrails to ensure:

-   Only approved tables can be queried
-   Only approved fields can be selected
-   Only approved models can be used
-   Sanitized query context
-   Controlled token usage
-   Rate-limit validation
-   Structured LLM output

#### Logical Flow

    SOC Analyst (Web UI)
            ↓
    Query Context Sanitization
            ↓
    Guardrails Validation
            ↓
    KQL Generation
            ↓
    Microsoft Sentinel (Log Analytics)
            ↓
    LLM Threat Analysis
            ↓
    Structured Findings
            ↓
    PDF Playbook Generation

 ![Agentic_AI_Message_Prompt](https://github.com/cfazuero1/agentic-ai/blob/main/ai_message.png)
------------------------------------------------------------------------

## 🌐 Web Application Features

### 🖥️ Interactive Hunt Interface

-   Model selection (restricted to allowed models)
-   Table selection (guardrail enforced)
-   Multi-select allowed fields
-   Time range configuration
-   Record limit configuration
-   Structured prompt input
-   Loading overlay during execution

------------------------------------------------------------------------

### 📊 Professional Results Page

The results page displays:

-   🔎 Search Summary (Table, Time Range, Device, UPN, Caller)
-   📌 Selected Fields
-   🧾 Investigation Rationale
-   🧠 Human-readable Findings (not raw JSON)
-   🛡️ MITRE ATT&CK Mapping
-   🔍 Executed KQL Query
-   📄 Downloadable Mitigation Playbook (PDF)

------------------------------------------------------------------------

## 🛡️ Guardrails System

### ✅ Allowed Tables

-   DeviceProcessEvents\
-   DeviceNetworkEvents\
-   DeviceLogonEvents\
-   DeviceFileEvents\
-   AzureActivity\
-   SigninLogs\
-   AzureNetworkAnalytics_CL\
-   AlertInfo\
-   AlertEvidence\
-   DeviceRegistryEvents

### ✅ Allowed Models

-   gpt-5-mini\
-   gpt-4.1-mini\
-   gpt-4.1

### 🔒 Enforced Validations

-   Table whitelist enforcement\
-   Field whitelist enforcement\
-   Model validation\
-   Token limit checks\
-   Rate limit checks\
-   Query sanitization\
-   Controlled LLM message format

------------------------------------------------------------------------

## 🔍 Threat Hunting Flow

### 1️⃣ Query Context Creation

-   Sanitizes user selections\
-   Applies defaults if missing\
-   Validates fields against allowed schema

### 2️⃣ KQL Query Execution

-   Dynamically builds KQL\
-   Applies time filter\
-   Applies device / caller / UPN filters\
-   Applies record limit

### 3️⃣ AI Threat Analysis

The LLM: - Reviews log records\
- Identifies suspicious behavior\
- Assesses severity\
- Maps to MITRE ATT&CK\
- Generates mitigation recommendations

### 4️⃣ Playbook Generation

A structured PDF is generated containing: - Executive Summary\
- Findings\
- Impact\
- MITRE Mapping\
- Containment Steps\
- Remediation Actions\
- Long-term Recommendations

------------------------------------------------------------------------

## 🏗️ Project Structure

    app.py
    EXECUTOR.py
    MODEL_MANAGEMENT.py
    GUARDRAILS.py
    PROMPT_MANAGEMENT.py
    PLAYBOOK.py
    keys.py
    templates/
    static/

------------------------------------------------------------------------

## 🔧 Requirements

    flask
    openai
    azure-identity
    azure-monitor-query
    reportlab
    python-dotenv

Install:

``` bash
pip install -r requirements.txt
```

------------------------------------------------------------------------

## 🔑 Configuration

`keys.py`

``` python
OPENAI_API_KEY = "your-api-key"
LOG_ANALYTICS_WORKSPACE_ID = "your-workspace-id"
```

------------------------------------------------------------------------

## 🚀 Running the Application

``` bash
python app.py
```

Open:

    http://127.0.0.1:5000

------------------------------------------------------------------------

## 🧠 Design Philosophy

This system follows an **Agentic AI model**:

-   Structured prompts\
-   Clear separation of system & user instructions\
-   Guardrail-controlled execution\
-   Human-readable reporting\
-   SOC-aligned investigation output\
-   Human oversight at final decision layer

------------------------------------------------------------------------

## 🔐 Security Considerations

-   No free-text KQL injection\
-   Strict field control\
-   Strict table control\
-   Controlled model selection\
-   Rate-limit monitoring\
-   Sanitized query context

------------------------------------------------------------------------

## 👩‍💻 Human Oversight

The AI assists but does not replace the SOC analyst.

All findings: - Require analyst validation\
- Are contextual recommendations\
- Should be verified before response actions

------------------------------------------------------------------------

## ✨ Future Improvements

-   Real-time progress tracking\
-   Streaming LLM output\
-   Multi-workspace support\
-   SOC metrics dashboard\
-   SOAR integration\
-   RBAC support\
-   Audit logging

------------------------------------------------------------------------
