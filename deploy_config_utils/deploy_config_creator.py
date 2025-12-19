
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
import os
from typing import Dict, List, Tuple, Optional, Any, Set

# Environment prefixes: normalized to lowercase keys at top-level
ENV_PREFIXES = {"q", "qa", "prod", "pr", "prd"}  # includes 'pr' to match examples

# Characters to strip at the very start (for key only) and to replace anywhere with '_'
KEY_STRIP_LEADING_CHARS = r"/\-\.\;\$\\"
KEY_REPLACE_CHARS = r'/\-\.\"\\"\#\!\:\?\;\[\]\*\}\${\\'

# Tokens to skip entirely
SKIP_TOKENS_CI = {"na", "n/a"}
SKIP_TOKENS_LITERAL = {"0"}

# Regex helpers
# env prefix like: qa: <spaces> <anything>, we only remove the "qa:" part for env handling
RE_ENV_PREFIX = re.compile(r'^\s*["\']?([A-Za-z]{1,10}):\s*')
RE_DRIVE_PREFIX = re.compile(r'^\s*([A-Za-z]):\s*')  # e.g., D:, A:
RE_STRIP_LEADING = re.compile(rf'^[{KEY_STRIP_LEADING_CHARS}]+')
RE_REPLACE_CHARS = re.compile(rf'[{KEY_REPLACE_CHARS}]+')
#ENV_SEPARATOR = re.compile(r'([A-Za-z]{1,10}):\s*([^,]+)')

KEY_PAIR_VALIDATION = r"^\s*[^,\s]+:[^,\s]+(?:\s*,\s*[^,\s]+:[^,\s]+){1,}\s*$"
EXTRACT_PAIR  = r"[^,\s]+:[^,\s]+"
EXTRACT_VALUES = r"[^,\s]+:\s*([^,\s]+)"

KEY_PAIR_VALIDATION_1 = r"^\s*[^,\s]+:\s*\\\\[^\\,\s]+(?:\\[^\\,\s]+)+(?:\s*,\s*[^,\s]+:\s*\\\\[^\\,\s]+(?:\\[^\\,\s]+)+){1,}\s*$"
EXTRACT_PAIR_1  =  r"\b[^,\s]+:\s*\\\\[^\\,\s]+(?:\\[^\\,\s]+)+"

KEY_PAIR_VALIDATION_2 = r"^\s*[^,\s]+:\s*[^,\s]+(?:\s*,\s*[^,\s]+:\s*[^,\s]+){1,}\s*$"
EXTRACT_PAIR_2  =  r"\b[^,\s]+:\s*[^,\s]+(?:[^,\s]+)+"


KEY_PAIR_VALIDATION_3 = r"^\s*[^,\s]+:\s*(?:/[^,\s]+|\\\\[^\\,\s]+(?:\\[^\\,\s]+)+)(?:\s*,?\s*[^,\s]+:\s*(?:/[^,\s]+|\\\\[^\\,\s]+(?:\\[^\\,\s]+)+)){1,}\s*$"
EXTRACT_PAIR_3  = r"[^,\s]+:\s*(?:/[^,\s]+|\\\\[^\\,\s]+(?:\\[^\\,\s]+)+)"


def tokenize(raw: str) -> List[str]:
    """Split input by newline first, then by commas, trim each token, keep non-empty."""
    tokens: List[str] = []
    for line in raw.splitlines():
        # for part in line.split(","):
        #     t = part.strip()
        #     if t:
        tokens.append(line)
    return tokens


def should_skip(token: str) -> bool:
    t = token.strip()
    if not t:
        return True
    if t in SKIP_TOKENS_LITERAL:
        return True
    if t.lower() in SKIP_TOKENS_CI:
        return True
    if "<" in t and ">" in t:
        return True
    return False

# === Merge algorithm for multi-env items in one line ===
def longest_common_prefix(lists: List[List[str]]) -> List[str]:
    if not lists:
        return []
    prefix = []
    for i in range(min(len(lst) for lst in lists)):
        token = lists[0][i]
        if all(i < len(lst) and lst[i] == token for lst in lists):
            prefix.append(token)
        else:
            break
    return prefix


def longest_common_suffix(lists: List[List[str]]) -> List[str]:
    if not lists:
        return []
    suffix = []
    min_len = min(len(lst) for lst in lists)
    for i in range(1, min_len + 1):
        token = lists[0][-i]
        if all(len(lst) >= i and lst[-i] == token for lst in lists):
            suffix.append(token)
        else:
            break
    suffix.reverse()
    return suffix

def key_to_tokens(key: str) -> List[str]:
    """Split a sanitized key into tokens by underscore, filter empties."""
    return [tok for tok in key.split("_") if tok]

def merge_env_keys(env_remainders: List[str]) -> str:
    """
    Given a list of env 'remainders' (paths/values after removing env prefix),
    produce a single merged key per your examples:
      - common prefix kept once
      - common suffix kept once
      - differing middle parts concatenated in order (deduped)
    """
    # Build sanitized keys (for tokenization), removing drive only for key
    sanitized_keys = []
    token_lists = []
    for rem in env_remainders:
        key_base = remove_drive_for_key(rem)
        k = make_key(key_base) or make_key(rem) or "value"
        sanitized_keys.append(k)
        token_lists.append(key_to_tokens(k))

    # Compute common prefix/suffix across all lists
    prefix = longest_common_prefix(token_lists)
    suffix = longest_common_suffix(token_lists)

    # Collect middle tokens from each list (excluding prefix & suffix)
    merged_middle: List[str] = []
    seen = set()

    for toks in token_lists:
        start = len(prefix)
        end = len(toks) - len(suffix) if len(suffix) <= len(toks) else 0
        mid = toks[start:end] if end >= start else []
        for t in mid:
            if t not in seen:
                merged_middle.append(t)
                seen.add(t)

    # Compose final tokens
    final_tokens = prefix + merged_middle + suffix
    final_key = "_".join(final_tokens) if final_tokens else "value"
    return final_key.lower()


def split_env_prefix(token: str) -> Tuple[Optional[str], str]:
    """
    If token starts with an env prefix (q:, qa:, QA:, prod:, pr:), return (env_lower, remainder_without_prefix).
    Otherwise, return (None, original_token).
    """
    m = RE_ENV_PREFIX.match(token)
    if not m:
        return None, token
    env = m.group(1).lower()
    if env in ENV_PREFIXES:
        # Remainder after the prefix + colon + optional spaces
        remainder = token[m.end():].strip()
        return env, remainder
    return None, token


def remove_drive_for_key(s: str) -> str:
    """If the string starts with a drive like X:, remove it for KEY building only."""
    m = RE_DRIVE_PREFIX.match(s)
    if m:
        return s[m.end():]
    return s


def make_key(from_text: str) -> str:
    t = RE_STRIP_LEADING.sub("", from_text)
    t = RE_REPLACE_CHARS.sub("_", t)
    t = re.sub(r"\s+", "_", t)
    t = re.sub(r"_+", "_", t).strip("_")
    return t.lower()


def ensure_unique(key: str, scope: Dict[str, object]):
    if key not in scope:
        return key
    return None

def find_pattern(token):
    if re.match(KEY_PAIR_VALIDATION, token):
        pattern = EXTRACT_PAIR
    elif re.match(KEY_PAIR_VALIDATION_1, token):
        pattern = EXTRACT_PAIR_1
    elif re.match(KEY_PAIR_VALIDATION_2, token):
        pattern = EXTRACT_PAIR_2
    elif re.match(KEY_PAIR_VALIDATION_3, token):
        pattern = EXTRACT_PAIR_3
    else:
        pattern = ''
    return pattern


def transform(raw_input: str) -> Dict:
    """
    Main transformer according to the requirements.
    Returns a dict with top-level direct mappings and env sub-objects.
    """
    result: Dict[str, object] = {}
    tokens = tokenize(raw_input)

    for tok in tokens:
        if should_skip(tok):
            continue

        if re.match(KEY_PAIR_VALIDATION, tok) or re.match(KEY_PAIR_VALIDATION_1, tok) or re.match(KEY_PAIR_VALIDATION_2, tok) or re.match(KEY_PAIR_VALIDATION_3, tok):
            pattern = find_pattern(tok)
            results = re.findall(EXTRACT_VALUES, tok)
            extract_pair = re.findall(pattern, tok)
            merged_key = merge_env_keys(results)
            for res in extract_pair:
                extract_value = res.split(":")
                # Top-level entry: value as-is; key built with drive removed only for key
                env, original_value = extract_value[0], extract_value[1].strip()
                sub = result.get(env)
                if not isinstance(sub, dict):
                    sub = {}
                    result[env] = sub
                key_base_for_key = remove_drive_for_key(merged_key)
                key = make_key(key_base_for_key) or make_key(merged_key) or "value"
                key = ensure_unique(key, sub)

                # Value under env is the remainder WITHOUT env prefix (as per your examples)
                if key:
                    sub[key] = original_value

        else:
            tok = tok.strip().replace('"', "")
            env, remainder = split_env_prefix(tok)
            if env is not None:
                # Create / get env sub-dict
                sub = result.get(env)
                if not isinstance(sub, dict):
                    sub = {}
                    result[env] = sub

                # Key derived from remainder (env prefix removed); also strip any drive only for key
                key_base_for_key = remove_drive_for_key(remainder)
                key = make_key(key_base_for_key) or make_key(remainder) or "value"

                key = ensure_unique(key, sub)

                # Value under env is the remainder WITHOUT env prefix (as per your examples)
                if key:
                    sub[key] = remainder
            else:
                # Top-level entry: value as-is; key built with drive removed only for key
                original_value = tok
                key_base_for_key = remove_drive_for_key(original_value)
                key = make_key(key_base_for_key) or make_key(original_value) or "value"
                key = ensure_unique(key, result)
                if key:
                    result[key] = original_value

    return result

"""
Split a config JSON into environment-specific files with env aliasing.

Usage:
    python split_env_config.py --in config.json --out ./env_out

Alias rules (customizable):
- pr, prod, prd  -> prd  (canonical: 'prd')
- qa, sit        -> qa   (canonical: 'qa')

Behavior:
- Top-level keys that are env blocks (dicts) are merged into their canonical env.
- Non-env top-level keys are treated as global and included in ALL env outputs.
- If the same key exists at global and env levels, the env value overrides.
"""

# Map aliases to canonical environment names
ENV_ALIASES: Dict[str, str] = {
    "pr": "prd",
    "prod": "prd",
    "prd": "prd",
    "qa": "qa",
    "sit": "qa",
    # You can add more, e.g. "uat": "uat", "dev": "dev", etc.
}

# Convenience set for quick membership checks
KNOWN_ENVS: Set[str] = set(ENV_ALIASES.keys())

def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def canonical_env(name: str) -> str:
    return ENV_ALIASES.get(name.lower())


def split_config_by_env(config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Produce per-environment dicts from a single config dict, applying aliases.

    Steps:
    1) Collect global (non-env) top-level pairs.
    2) For each env-like top-level key (dict), merge into its canonical env bucket.
       - If multiple alias blocks map to same canonical env (e.g., pr + prd), they merge.
       - Later alias blocks override earlier ones at key conflict.
    3) For each canonical env, merge: globals + env bucket (env overrides).
    """
    # Identify env blocks and globals
    env_blocks: Dict[str, Dict[str, Any]] = {}  # canonical_env -> merged dict
    globals_dict: Dict[str, Any] = {}

    for key, value in config.items():
        can = canonical_env(key)
        if can and isinstance(value, dict):
            # Merge into the canonical environment bucket
            if can not in env_blocks:
                env_blocks[can] = {}
            env_blocks[can].update(value)  # alias order matters: later overrides earlier
        else:
            # Treat as global
            globals_dict[key] = value

    # If no env blocks found, return a single default config
    if not env_blocks:
        return {"default": config}

    # Compose final per-env outputs: globals + env specifics
    per_env: Dict[str, Dict[str, Any]] = {}
    for can_env, env_dict in env_blocks.items():
        merged = {}
        merged.update(globals_dict)
        merged.update(env_dict)  # env overrides globals at same key
        per_env[can_env] = merged

    return per_env


def write_env_files(per_env: Dict[str, Dict[str, Any]], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    for env, data in per_env.items():
        out_path = os.path.join(output_dir, f"deploy_config_{env}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {out_path}")

def main():
    input_file_path = ".\\Artifacts\\deploy_config_R4.txt"
    output_file_path = ".\\Artifacts\\output_file.json"
    output_dir = ".\\Artifacts"

    with open(input_file_path, 'r', encoding="utf-8") as infile, open(output_file_path, 'w', encoding="utf-8") as outfile:
        lines = infile.read()
        result = transform(lines)
        output = json.dumps(result, indent=4, ensure_ascii=False)
        outfile.write(output)

    config = load_json(output_file_path)
    per_env = split_config_by_env(config)
    write_env_files(per_env, output_dir)

    env_list = ", ".join(sorted(per_env.keys()))
    print(f"Canonical environments generated: {env_list}")

if __name__ == "__main__":
    main()
