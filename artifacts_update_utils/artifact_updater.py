
#!/usr/bin/env python3
"""
Recursively traverse specified directories, read JSON files whose names start with given prefixes,
apply prefix-specific updates, and write changes back to disk.

Usage (CLI):
    python read_update_jsons.py \
        --dirs "/path/to/dir1" "/path/to/dir2" \
        --prefixes "sbys" "rule" \
        [--print-paths-only] [--dry-run] [--no-backup]

Examples:
    # Find and update files starting with 'sbys' or 'rule' in two directories
    python read_update_jsons.py -d "./input" "./more" -p "sbys" "rule"

    # Only list matched paths grouped by directory
    python read_update_jsons.py -d "./input" -p "sbys" "rule" --print-paths-only

    # Preview updates without writing to disk
    python read_update_jsons.py -d "./input" -p "sbys" "rule" --dry-run
"""

import json
import sys
from pathlib import Path
from typing import Iterable, List, Dict, Any, Tuple, Optional
import re

qa_deploy_config = dict()
prod_deploy_config = dict()

# ------------------------------
# Matching & traversal utilities
# ------------------------------

def file_matches_prefixes(path: Path, prefixes: Iterable[str]) -> bool:
    """Return True if the filename starts with any of the prefixes and ends with .json."""
    name = path.name
    if not name.lower().endswith(".json"):
        return False
    return any(name.startswith(prefix) for prefix in prefixes)


def walk_and_collect_json_paths(root_dirs: Iterable[Path], prefixes: Iterable[str]) -> List[Path]:
    """
    Recursively walk root_dirs and return a list of JSON file paths whose names start with prefixes.
    """
    matched_paths: List[Path] = []
    for root in root_dirs:
        if not root.exists():
            print(f"[warn] Directory does not exist: {root}", file=sys.stderr)
            continue
        if not root.is_dir():
            print(f"[warn] Not a directory: {root}", file=sys.stderr)
            continue

        # Traverse and filter by prefix
        for path in root.rglob("*.json"):
            if file_matches_prefixes(path, prefixes):
                matched_paths.append(path)

    return matched_paths


def print_matched_paths(paths: List[Path]) -> None:
    """Print a grouped view of matched paths by their parent directory."""
    from collections import defaultdict
    grouped = defaultdict(list)
    for p in paths:
        grouped[p.parent].append(p)

    for parent, files in sorted(grouped.items(), key=lambda kv: str(kv[0])):
        print(f"\n# Directory: {parent}")
        for f in sorted(files):
            print(f" - {f.name}")


# ------------------------------
# JSON I/O
# ------------------------------

def read_json_file(path: Path) -> Tuple[Path, Optional[Dict[str, Any]], Optional[str]]:
    """
    Safely read and parse a JSON file.
    Returns (path, data, error_message). If successful, error_message is None.
    """
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            data = json.load(f)
        return path, data, None
    except json.JSONDecodeError as e:
        return path, None, f"JSON decode error: {e}"
    except OSError as e:
        return path, None, f"I/O error: {e}"
    except Exception as e:
        return path, None, f"Unexpected error: {e}"


def write_json_file(path: Path, data: Dict[str, Any], backup: bool = True) -> Optional[str]:
    """
    Overwrite the JSON file with the updated 'data'.
    If backup=True, creates a .bak next to the original before writing.
    Returns an error message string if something goes wrong, otherwise None.
    """
    try:
        if backup and path.exists():
            backup_path = path.with_suffix(path.suffix + ".bak")
            # If an older backup exists, replace it
            if backup_path.exists():
                backup_path.unlink()
            path.replace(backup_path)

        # Write pretty-printed UTF-8 JSON
        text = json.dumps(data, ensure_ascii=False, indent=2)
        with path.open("w", encoding="utf-8") as f:
            f.write(text)

        return None
    except OSError as e:
        return f"I/O error while writing: {e}"
    except Exception as e:
        return f"Unexpected write error: {e}"


# ------------------------------
# Prefix-specific update handlers
# ------------------------------

def process_sbys_json(path: Path, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform JSON for files starting with 'sbys'. Return updated dict.
    Updates the 'senderCode' inside the first item of 'codes' using process_sender_code().
    """
    updated = dict(data)  # copy to avoid mutating the input

    codes = updated.get("codes")
    if isinstance(codes, list) and codes:
        codelist = codes[0]
        if isinstance(codelist, dict):
            # SenderCode
            original_sender_code = codelist.get("senderCode")
            processed_sender_code = inject_variables_for_codelist(original_sender_code)
            codelist["senderCode_original"] = original_sender_code
            codelist["senderCode"] = processed_sender_code
            # print("Sender Code = ", original_sender_code," --> ", processed_sender_code)

            # receiverCode
            original_receiver_code = codelist.get("receiverCode")
            processed_receiver_code = inject_variables_for_codelist(original_receiver_code)
            codelist["receiverCode_original"] = original_receiver_code
            codelist["receiverCode"] = processed_receiver_code

            # Description
            original_description = codelist.get("description")
            processed_description = inject_variables_for_codelist(original_description)
            codelist["description_original"] = original_description
            codelist["description"] = processed_description
            # print("Description: ", original_description, " --> ", processed_description)

            # text1
            process_field(codelist, "text1")
            process_field(codelist, "text2")
            process_field(codelist, "text3")
            process_field(codelist, "text4")
            process_field(codelist, "text5")
            process_field(codelist, "text6")
            process_field(codelist, "text7")
            process_field(codelist, "text8")
            process_field(codelist, "text9")


            # Assign the modified item back to the list (optional since dict is mutable)
            updated["codes"][0] = codelist

    # If you want to tag the file as processed or add metadata:
    # updated["processed_by"] = "sbys_handler"
    # meta = updated.get("metadata", {})
    # meta["source_file"] = path.name
    # updated["metadata"] = meta

    return updated

def replace_values_across_separators(
    text: str,
    qa_deploy_config: Dict[str, object],
    separators: Iterable[str] = ("|", ".", "/", "\\", " "),
    case_insensitive: bool = True
) -> str:
    """
    Replace any occurrence of config values in `text` with ${key}, even if the value
    spans across separators (e.g., 'abc/svc'). Uses a custom boundary definition:
    start/end of string or one of the separators.

    Prefers longer matches first to avoid partial replacements.
    """
    if not text:
        return text

    # Normalize config: map normalized string values -> key
    norm = (lambda s: str(s).lower()) if case_insensitive else str
    value_to_key = {norm(v): k for k, v in qa_deploy_config.items()}

    # Sort values by length descending for longest-match-first
    values_sorted = sorted(value_to_key.keys(), key=len, reverse=True)

    # Build separator class and boundary lookarounds
    sep_class = "[" + "".join(re.escape(s) for s in separators) + "]"
    left_boundary  = rf"(?:(?<=^)|(?<={sep_class}))"
    right_boundary = rf"(?:(?=$)|(?={sep_class}))"

    # Build alternation of escaped values
    alternation = "|".join(re.escape(v) for v in values_sorted)
    if case_insensitive:
        regex = re.compile(left_boundary + f"({alternation})" + right_boundary, re.IGNORECASE)
    else:
        regex = re.compile(left_boundary + f"({alternation})" + right_boundary)

    def repl(m: re.Match) -> str:
        matched = m.group(1)
        key = value_to_key[norm(matched)]
        return f"${{{{{key}}}}}"

    return regex.sub(repl, text)

def inject_variables_for_codelist(input_string:str) -> str:
    if type(input_string) in [bool, int, None]:
        return input_string

    code = replace_values_across_separators(input_string, qa_deploy_config)
    return code

def inject_variables_for_cd(input_string:str):
    if type(input_string) in [bool, int, None]:
        return input_string

    result = replace_values_across_separators(input_string, qa_deploy_config)
    if result != input_string:
        return result

    return input_string.strip()

def process_field(codelist, field_name):
    original_text = codelist.get(field_name)
    processed_text = inject_variables_for_codelist(original_text)
    codelist[field_name + "_original"] = original_text
    codelist[field_name] = processed_text
    print(field_name, ": ", original_text, " --> ", processed_text)

def process_cd_json(path: Path, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform JSON for files starting with 'rule' and watchdir. Return updated dict.
    """
    updated = dict(data)
    rules = updated.get("rules", [])
    watchdirs = updated.get("watchDirList", {})
    if rules:
        #updated["rules_count"] = len(rules)
        #updated["processed_by"] = "rule_handler"
        if isinstance(rules, list) and rules:
            codelist = rules[0]
            if isinstance(codelist, dict):
                for k, code in codelist.items():
                    updated_code = inject_variables_for_cd(code)
                    codelist[k] = updated_code
        return updated
    elif watchdirs:
        updated_wd = {}
        if isinstance(watchdirs, dict):
            for key, value in watchdirs.items():
                for k, v in value.items():
                    updated_code = inject_variables_for_cd(v)
                    value[k] = updated_code
                updated_key = inject_variables_for_cd(key)
                updated_wd[updated_key] = value

            updated['watchDirList'] = updated_wd
    return updated


def process_default_json(path: Path, data: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback transformation for unmatched prefixes."""
    updated = dict(data)
    updated["processed_by"] = "default_handler"
    return updated


def dispatch_update(path: Path, data: Dict[str, Any]) -> Dict[str, Any]:
    """Select the appropriate handler based on filename."""
    name = path.name.lower()
    if name.startswith("sbys"):
        return process_sbys_json(path, data)
    elif name.startswith("rule") or name.startswith("watch"):
        return process_cd_json(path, data)
    # Add more branches as needed:
    # elif name.startswith("conf"):
    #     return process_conf_json(path, data)
    else:
        return process_default_json(path, data)


def read_json(filepath: str) -> Dict[str, Any]:
    """
    Reads a JSON file and returns its contents as a dictionary.

    Args:
        filepath (str): Path to the JSON file.

    Returns:
        dict: Parsed JSON data.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    with path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)

    return data


# ------------------------------
# Main CLI orchestration
# ------------------------------

def load_config_files():
    # qa_config_file_path = "./Artifacts/deploy_config_qa.json"
    qa_config_file_path = "./Artifacts/deploy_config_default.json"

    prod_config_file_path = "./Artifacts/deploy_config_prd.json"
    global qa_deploy_config, prod_deploy_config

    try:
        qa_deploy_config = read_json(qa_config_file_path)
        prod_deploy_config = read_json(prod_config_file_path)
    except Exception as e:
        print(f"Error: {e}")


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Recursively read and update JSON files whose names start with given prefixes."
    )
    parser.add_argument(
        "--dirs", "-d", nargs="+", required=True,
        help="List of root directories to traverse."
    )
    parser.add_argument(
        "--prefixes", "-p", nargs="+", required=True,
        help="Filename prefixes to match (e.g., sbys, rule)."
    )
    parser.add_argument(
        "--print-paths-only", action="store_true",
        help="Only print matched file paths grouped by directory (do not read/update)."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Read and show updates but do NOT write changes to disk."
    )
    parser.add_argument(
        "--no-backup", action="store_true",
        help="Write changes without creating .bak backups."
    )

    args = parser.parse_args(argv)

    # Normalize inputs
    dir_paths = [Path(d).resolve() for d in args.dirs]
    prefixes = list(args.prefixes)

    load_config_files()

    # Find matching files and print grouped view
    json_paths = walk_and_collect_json_paths(dir_paths, prefixes)
    print_matched_paths(json_paths)

    if args.print_paths_only:
        # Only listing of paths requested
        return 0

    # Read, update, and optionally write back
    results: List[Dict[str, Any]] = []
    for path in sorted(json_paths):
        p, data, read_err = read_json_file(path)
        if read_err:
            results.append({"path": str(p), "data": None, "error": read_err})
            continue

        # Dispatch to appropriate transformer based on filename
        try:
            updated = dispatch_update(p, data)
        except Exception as e:
            results.append({"path": str(p), "data": None, "error": f"Update error: {e}"})
            continue

        if args.dry_run:
            # Skip writing; just record success
            results.append({"path": str(p), "data": updated, "error": None})
        else:
            write_err = write_json_file(p, updated, backup=(not args.no_backup))
            results.append({"path": str(p), "data": updated, "error": write_err})

    # Summary
    total = len(results)
    errors = sum(1 for r in results if r["error"])
    mode = "DRY-RUN" if args.dry_run else "WRITE"
    print(f"\n[{mode}] Summary -> Files: {total}, Errors: {errors}", file=sys.stderr)
    with open(".\\Artifacts\\Artifacts_result.log", "w", encoding="utf-8") as f:
        for r in results:
            if r["error"]:
                print(f"[error] {r['path']}: {r['error']}", file=sys.stderr)
                f.write(f"[error] {r['path']}: {r['error']}")
            else:
                status = "UPDATED" if not args.dry_run else "PREVIEW"
                f.write(f"\n=== {status}: {r['path']} ===")
                print(f"\n=== {status}: {r['path']} ===")
                try:
                    print(json.dumps(r["data"], ensure_ascii=False, indent=2)[:2000])
                    f.write(json.dumps(r["data"], ensure_ascii=False, indent=2)[:2000])
                except Exception:
                    print("[warn] Could not pretty-print updated JSON.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
