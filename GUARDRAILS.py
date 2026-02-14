
from __future__ import annotations
import re
from typing import Any, Iterable

# Add this to GUARDRAILS.py

ALLOWED_TABLES = [
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "SigninLogs",
    "AzureActivity"
]

ALLOWED_FIELDS = {
    "DeviceProcessEvents": { "TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine" },
    "DeviceNetworkEvents": { "TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort" },
    "DeviceLogonEvents": { "TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName" },
    "AlertInfo": {},  # No fields specified in tools
    "AlertEvidence": {},  # No fields specified in tools
    "DeviceFileEvents": {"TimeGenerated","ActionType","DeviceName","FileName","FolderPath","InitiatingProcessAccountName","SHA256"},
    "DeviceRegistryEvents": {},  # No fields specified in tools
    "AzureNetworkAnalytics_CL": { "TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d" },
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category" },
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails" },
}

ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gpt-4.1":      {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 1.00, "cost_per_million_output": 8.00,  "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 30_000_000}},
    "gpt-5-mini":   {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 0.25, "cost_per_million_output": 2.00,  "tier": {"free": None,   "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gpt-5":        {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 40_000_000}}
}

def validate_model(model: str):
    if model not in ALLOWED_MODELS:
        raise ValueError(f"Model '{model}' is not allowed.")

def validate_tables_and_fields(table_name, fields):
    # --- normalize fields ---
    if fields is None:
        fields = []

    # If someone passed a single string, split it into a list
    if isinstance(fields, str):
        fields = [f.strip() for f in fields.replace("\n", ",").split(",") if f.strip()]

    # If someone passed a list but it contains a single comma-separated string, split it too
    if isinstance(fields, list) and len(fields) == 1 and isinstance(fields[0], str) and "," in fields[0]:
        fields = [f.strip() for f in fields[0].replace("\n", ",").split(",") if f.strip()]

    # --- then your existing allowlist checks below ---
    if table_name not in ALLOWED_TABLES:
        raise ValueError(f"Table '{table_name}' is not allowed.")

    allowed = set(ALLOWED_FIELDS.get(table_name, []))
    for field in fields:
        if field not in allowed:
            raise ValueError(f"Field '{field}' is not allowed for table '{table_name}'.")

def _as_str(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, (list, tuple, set)):
        return ", ".join(str(i) for i in x)
    return str(x)

def _as_list(x: Any) -> list[str]:
    if x is None:
        return []
    if isinstance(x, (list, tuple, set)):
        return [str(i) for i in x if i is not None and str(i).strip() != ""]
    s = str(x).strip()
    return [s] if s else []

def _sanitize_identifier(s: Any) -> str:
    s = _as_str(s).strip()
    s = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9_]+", s):
        raise ValueError(f"Invalid identifier: {s!r}")
    return s

def _sanitize_prefix(s: Any) -> str:
    s = _as_str(s).strip()
    s = s.replace("\r", " ").replace("\n", " ")
    s = s.replace(";", "").replace("|", "").replace("`", "")
    return s

def validate_web_inputs(
    table_name: Any,
    fields: Any,
    allowed_tables: Iterable[str],
    allowed_fields_by_table: dict[str, list[str]],
) -> tuple[str, list[str]]:

    clean_table = _sanitize_identifier(table_name)

    if clean_table not in set(allowed_tables):
        raise ValueError(f"Table {clean_table!r} is not allowed.")

    selected_fields = _as_list(fields)
    allowed_fields_set = set(allowed_fields_by_table.get(clean_table, []))

    clean_fields: list[str] = []
    for f in selected_fields:
        cf = _sanitize_identifier(f)
        if cf not in allowed_fields_set:
            raise ValueError(f"Field {cf!r} is not allowed for table {clean_table!r}.")
        clean_fields.append(cf)

    if not clean_fields:
        raise ValueError("You must select at least one field.")

    return clean_table, clean_fields
