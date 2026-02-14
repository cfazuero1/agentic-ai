from colorama import Fore, Style
import tiktoken
import GUARDRAILS

# ---- Settings ---------------------------------------------------------------

# https://platform.openai.com/settings/organization/limits
CURRENT_TIER = "4"  # "free", "1", "2", "3", "4", "5" 
DEFAULT_MODEL = "gpt-5-mini"
WARNING_RATIO = 0.80  # 80%

def money(usd):
    return f"${usd:.6f}" if usd < 0.01 else f"${usd:.2f}"

def color_for_usage(used, limit):
    if limit is None:
        return Fore.LIGHTGREEN_EX
    if used > limit:
        return Fore.LIGHTRED_EX
    if used >= WARNING_RATIO * limit:
        return Fore.LIGHTYELLOW_EX
    return Fore.LIGHTGREEN_EX

def colorize(label, used, limit):
    col = color_for_usage(used, limit)
    lim = "∞" if limit is None else str(limit)
    return f"{label}: {col}{used}/{lim}{Style.RESET_ALL}"

def estimate_cost(input_tokens, output_tokens, model_info):
    cin = input_tokens * model_info["cost_per_million_input"] / 1_000_000.0
    cout = output_tokens * model_info["cost_per_million_output"] / 1_000_000.0
    return cin + cout

def print_model_table(input_tokens, current_model, tier, assumed_output_tokens=500):
    print(f"Model limits and estimated total cost:{Fore.WHITE}\n")
    for name, info in GUARDRAILS.ALLOWED_MODELS.items():
        tpm_limit = info["tier"].get(tier)
        usage_text = colorize("input limit", input_tokens, info["max_input_tokens"])
        tpm_text = colorize("rate_limit", input_tokens, tpm_limit)
        est = estimate_cost(input_tokens, assumed_output_tokens, info)
        tag = f"{Fore.CYAN} <-- (current){Fore.WHITE}" if name == current_model else ""
        print(f"{name:<12} | {usage_text:<35} | {tpm_text:<32} | out_max: {info['max_output_tokens']:<6} | est_cost: {money(est)}{tag}")
    print("")

def assess_limits(model_name, input_tokens, tier):
    info = GUARDRAILS.ALLOWED_MODELS[model_name]
    msgs = []

    # Input cap
    usage_txt = colorize("input limit", input_tokens, info["max_input_tokens"])
    if input_tokens > info["max_input_tokens"]:
        msgs.append(f"🚨 ERROR: {usage_txt} exceeds the input limit for {model_name}.")
    elif input_tokens >= WARNING_RATIO * info["max_input_tokens"]:
        msgs.append(f"⚠️ WARNING: {usage_txt} is at least 80% of the input limit for {model_name}.")
    else:
        msgs.append(f"✅ Safe: {usage_txt} is within the input limit for {model_name}.")

    # TPM cap
    tpm_limit = info["tier"].get(tier)
    tpm_txt = colorize("rate_limit", input_tokens, tpm_limit)
    if tpm_limit is not None:
        if input_tokens > tpm_limit:
            msgs.append(f"⚠️ WARNING: {tpm_txt} exceeds the TPM rate limit for {model_name} ({tpm_limit}) — may be too large.")
        elif input_tokens >= WARNING_RATIO * tpm_limit:
            msgs.append(f"⚠️ WARNING: {tpm_txt} is at least 80% of the TPM rate limit for {model_name}.")
        else:
            msgs.append(f"✅ Safe: {tpm_txt} is within the TPM rate limit for {model_name}.")
    else:
        msgs.append(f"ℹ️ No TPM tier limit known for {model_name} at tier '{tier}'.")

    if input_tokens > info["max_input_tokens"] or (tpm_limit is not None and input_tokens > tpm_limit):
        msgs += [
            "",
            "Try these to make it smaller:",
            " - Focus on one user or device",
            " - Use a shorter time range",
            " - Remove extra context you don't need",
        ]

    print("\n".join(msgs))
    print("")

def choose_model(model_name, input_tokens, tier=CURRENT_TIER, assumed_output_tokens=500, interactive=True):
    """
    Web-compatible model selection.
    Takes the user-selected model and validates it.
    Does NOT prompt for console input.
    """

    # Validate model exists
    if model_name not in GUARDRAILS.ALLOWED_MODELS:
        print(f"Unknown model '{model_name}'. Defaulting to {DEFAULT_MODEL}.")
        model_name = DEFAULT_MODEL

    info = GUARDRAILS.ALLOWED_MODELS[model_name]

    # Check limits
    tpm_limit = info["tier"].get(tier)
    over_input = input_tokens > info["max_input_tokens"]
    over_tpm = (tpm_limit is not None) and (input_tokens > tpm_limit)

    if over_input or over_tpm:
        msg = "input limit" if over_input else "TPM rate limit"
        print(f"WARNING: input may exceed {model_name}'s {msg}.")

    # Estimate cost (optional)
    try:
        est = estimate_cost(input_tokens, assumed_output_tokens, info)
        print(f"Estimated cost: {money(est)}")
    except Exception:
        pass

    return model_name

def count_tokens(messages, model):
    """
    Cheap estimate for chat messages.
    """
    try:
        enc = tiktoken.encoding_for_model(model)
    except KeyError:
        enc = tiktoken.get_encoding("cl100k_base")

    text = ""
    for m in messages:
        text += m.get("role", "") + " " + m.get("content", "") + "\n"
    return len(enc.encode(text))



def choose_model_web(current_model: str, input_tokens: int, tier: str = CURRENT_TIER, overrides: dict | None = None) -> dict:
    """
    Web-friendly model selection:
    - Keeps the user's selected model unless it exceeds limits.
    - Uses tier for rate-limit warnings.
    - Allows optional overrides for *warning/selection* only.
    Returns dict with chosen model and assessment messages.
    """
    overrides = overrides or {}
    # Validate model exists
    if current_model not in GUARDRAILS.ALLOWED_MODELS:
        current_model = DEFAULT_MODEL

    info = GUARDRAILS.ALLOWED_MODELS[current_model]
    max_input = overrides.get("max_input_tokens", info["max_input_tokens"])
    tpm_limit = overrides.get("tier_tpm_limit", info["tier"].get(tier))

    # If input is above max input, choose the cheapest model that fits
    if input_tokens > max_input:
        # Find models that can fit input_tokens (consider overrides per-model not supported; use native caps)
        candidates = []
        for name, inf in GUARDRAILS.ALLOWED_MODELS.items():
            if input_tokens <= inf["max_input_tokens"]:
                candidates.append((name, inf["cost_per_million_input"]))
        if candidates:
            candidates.sort(key=lambda x: x[1])
            chosen = candidates[0][0]
            return {"model": chosen, "notes": [f"Selected {chosen} because {current_model} input cap would be exceeded."]}
        # If none fit, return current and let OpenAI error handler handle it
        return {"model": current_model, "notes": ["No model found that fits the estimated input size."]}

    # If rate limit looks risky, suggest but do not force
    notes = []
    if tpm_limit is not None and input_tokens >= WARNING_RATIO * tpm_limit:
        notes.append("Estimated tokens are close to (or above) the tier rate limit; reduce log limit or choose a different model/tier.")
    return {"model": current_model, "notes": notes}
