"""Rule evaluator — applies loaded rules against a normalized IR and produces findings."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding data class
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    status: str          # "pass" | "fail" | "error" | "not_applicable" | "manual_check"
    description: str = ""
    remediation: str = ""
    frameworks: dict = field(default_factory=dict)
    affected_paths: list[str] = field(default_factory=list)
    affected_values: list[Any] = field(default_factory=list)
    details: str = ""
    source_rule_file: str = ""
    manual_result: str = ""  # "confirmed_ok" | "needs_attention" | "" (not reviewed)

    def to_dict(self) -> dict:
        from fireaudit.data.framework_urls import get_control_url

        framework_links: dict[str, dict[str, str]] = {}
        for fw, controls in self.frameworks.items():
            links: dict[str, str] = {}
            items = controls if isinstance(controls, list) else [controls]
            for ctrl in items:
                url = get_control_url(fw, ctrl)
                if url:
                    links[ctrl] = url
            if links:
                framework_links[fw] = links

        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "status": self.status,
            "description": self.description,
            "remediation": self.remediation,
            "frameworks": self.frameworks,
            "framework_links": framework_links,
            "affected_paths": self.affected_paths,
            "affected_values": [str(v) for v in self.affected_values],
            "details": self.details,
            "source_rule_file": self.source_rule_file,
            "manual_result": self.manual_result,
        }


# ---------------------------------------------------------------------------
# IR path resolution
# ---------------------------------------------------------------------------

def resolve_path(ir: dict, path: str) -> Any:
    """Resolve a dot-notation path into the IR, supporting list iteration.

    Path segments may include:
      - normal keys: "admin_access.ssh_settings.version"
      - list index:  "firewall_policies[0].action"
      - list wildcard: "firewall_policies[*].action"  (returns list of values)
    """
    parts = _split_path(path)
    return _resolve(ir, parts)


def _split_path(path: str) -> list[str | int | None]:
    """Split a dot-notation path into resolved segments."""
    result: list[str | int | None] = []
    for raw in path.split("."):
        if "[" in raw:
            key, idx_str = raw.split("[", 1)
            idx_str = idx_str.rstrip("]")
            if key:
                result.append(key)
            result.append(None if idx_str == "*" else int(idx_str))
        else:
            result.append(raw)
    return result


def _resolve(obj: Any, parts: list) -> Any:
    if not parts:
        return obj
    part = parts[0]
    rest = parts[1:]

    if part is None:
        # Wildcard: iterate list
        if not isinstance(obj, list):
            return []
        results: list[Any] = []
        for item in obj:
            sub = _resolve(item, rest)
            if sub is not None:
                results.append(sub)
        return results

    if isinstance(part, int):
        if not isinstance(obj, list) or part >= len(obj):
            return None
        return _resolve(obj[part], rest)

    if isinstance(obj, dict):
        return _resolve(obj.get(part), rest)

    return None


# ---------------------------------------------------------------------------
# Condition evaluators
# ---------------------------------------------------------------------------

def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "enable", "enabled", "1")
    if isinstance(value, int):
        return bool(value)
    return None


class _Condition:
    """Evaluates a single condition dict against a resolved value."""

    def check(self, condition: dict, value: Any, path: str) -> tuple[bool, str]:
        """Return (passed, detail_message)."""
        ctype = condition.get("type", "eq")

        if ctype == "eq":
            return self._eq(condition, value)
        elif ctype == "neq":
            passed, msg = self._eq(condition, value)
            return not passed, msg
        elif ctype == "gt":
            return self._compare(condition, value, "gt")
        elif ctype == "gte":
            return self._compare(condition, value, "gte")
        elif ctype == "lt":
            return self._compare(condition, value, "lt")
        elif ctype == "lte":
            return self._compare(condition, value, "lte")
        elif ctype == "in":
            return self._in(condition, value)
        elif ctype == "not_in":
            passed, msg = self._in(condition, value)
            return not passed, msg
        elif ctype == "contains":
            return self._contains(condition, value)
        elif ctype == "not_contains":
            passed, msg = self._contains(condition, value)
            return not passed, msg
        elif ctype == "intersects":
            return self._intersects(condition, value)
        elif ctype == "not_intersects":
            passed, msg = self._intersects(condition, value)
            return not passed, msg
        elif ctype == "is_true":
            b = _coerce_bool(value)
            return (b is True, f"expected true, got {value!r}")
        elif ctype == "is_false":
            b = _coerce_bool(value)
            return (b is False, f"expected false, got {value!r}")
        elif ctype == "is_null":
            return (value is None, f"expected null, got {value!r}")
        elif ctype == "is_not_null":
            return (value is not None, f"expected non-null, got None")
        elif ctype == "is_empty":
            return (not value, f"expected empty, got {value!r}")
        elif ctype == "is_not_empty":
            return (bool(value), f"expected non-empty, got {value!r}")
        elif ctype == "regex":
            return self._regex(condition, value)
        elif ctype == "not_regex":
            passed, msg = self._regex(condition, value)
            return not passed, msg
        elif ctype == "list_all":
            return self._list_all(condition, value)
        elif ctype == "list_any":
            return self._list_any(condition, value)
        elif ctype == "count_gt":
            return self._count(condition, value, "gt")
        elif ctype == "count_eq":
            return self._count(condition, value, "eq")
        elif ctype == "count_lt":
            return self._count(condition, value, "lt")
        elif ctype == "exists_where":
            return self._exists_where(condition, value)
        elif ctype == "not_exists_where":
            passed, msg = self._exists_where(condition, value)
            return not passed, msg
        else:
            return False, f"unknown condition type: {ctype!r}"

    def _eq(self, condition: dict, value: Any) -> tuple[bool, str]:
        expected = condition.get("value")
        if isinstance(expected, str) and isinstance(value, str):
            passed = value.lower() == expected.lower()
        else:
            passed = value == expected
        return passed, f"expected {expected!r}, got {value!r}"

    def _compare(self, condition: dict, value: Any, op: str) -> tuple[bool, str]:
        expected = condition.get("value")
        try:
            v = float(value)
            e = float(expected)
        except (TypeError, ValueError):
            return False, f"cannot compare {value!r} and {expected!r}"
        ops = {"gt": v > e, "gte": v >= e, "lt": v < e, "lte": v <= e}
        return ops[op], f"{op}({e}): got {v}"

    def _in(self, condition: dict, value: Any) -> tuple[bool, str]:
        values = condition.get("values", [])
        vals_lower = [str(v).lower() for v in values]
        v_str = str(value).lower() if value is not None else ""
        return v_str in vals_lower, f"expected one of {values!r}, got {value!r}"

    def _contains(self, condition: dict, value: Any) -> tuple[bool, str]:
        needle = str(condition.get("value", "")).lower()
        if isinstance(value, str):
            return needle in value.lower(), f"expected to contain {needle!r}"
        if isinstance(value, list):
            items_lower = [str(i).lower() for i in value]
            return needle in items_lower, f"expected list to contain {needle!r}"
        return False, f"cannot check contains on {type(value)}"

    def _intersects(self, condition: dict, value: Any) -> tuple[bool, str]:
        """Check whether value (list) shares any element with condition values list."""
        expected = [str(v).lower() for v in condition.get("values", [])]
        if isinstance(value, list):
            actual = [str(v).lower() for v in value]
        else:
            actual = [str(value).lower()] if value is not None else []
        overlap = set(actual) & set(expected)
        return bool(overlap), f"expected intersection with {expected!r}, got {actual!r}"

    def _regex(self, condition: dict, value: Any) -> tuple[bool, str]:
        pattern = condition.get("value", "")
        if value is None:
            return False, f"regex match on null value"
        matched = bool(re.search(pattern, str(value), re.IGNORECASE))
        return matched, f"regex {pattern!r} {'matched' if matched else 'did not match'} {value!r}"

    def _list_all(self, condition: dict, value: Any) -> tuple[bool, str]:
        """All items in value (list) must satisfy the sub-condition."""
        if not isinstance(value, list):
            return False, f"expected list for list_all, got {type(value)}"
        sub = condition.get("condition", {})
        checker = _Condition()
        for item in value:
            passed, msg = checker.check(sub, item, "")
            if not passed:
                return False, f"item {item!r} failed: {msg}"
        return True, "all items passed"

    def _list_any(self, condition: dict, value: Any) -> tuple[bool, str]:
        """At least one item in value (list) must satisfy the sub-condition."""
        if not isinstance(value, list):
            return False, f"expected list for list_any, got {type(value)}"
        sub = condition.get("condition", {})
        checker = _Condition()
        for item in value:
            passed, _ = checker.check(sub, item, "")
            if passed:
                return True, "at least one item passed"
        return False, "no items satisfied condition"

    def _count(self, condition: dict, value: Any, op: str) -> tuple[bool, str]:
        expected = int(condition.get("value", 0))
        count = len(value) if isinstance(value, list) else (1 if value is not None else 0)
        ops = {"gt": count > expected, "eq": count == expected, "lt": count < expected}
        return ops[op], f"count {op}({expected}): got {count}"

    def _exists_where(self, condition: dict, value: Any) -> tuple[bool, str]:
        """Check if any item in a list satisfies a set of sub-conditions (field: condition pairs)."""
        if not isinstance(value, list):
            return False, f"expected list for exists_where"
        where = condition.get("where", {})
        checker = _Condition()
        for item in value:
            if not isinstance(item, dict):
                continue
            match = True
            for field_key, sub_cond in where.items():
                field_val = item.get(field_key)
                passed, _ = checker.check(sub_cond, field_val, field_key)
                if not passed:
                    match = False
                    break
            if match:
                return True, f"found matching item"
        return False, f"no item matched where conditions"


# ---------------------------------------------------------------------------
# Main evaluator
# ---------------------------------------------------------------------------

class RuleEvaluator:
    """Evaluates a list of loaded rules against a normalized IR."""

    def __init__(self, rules: list[dict]) -> None:
        self.rules = rules
        self._cond_checker = _Condition()

    def evaluate(self, ir: dict, vendor: str | None = None) -> list[Finding]:
        """Evaluate all rules and return a list of Findings."""
        findings: list[Finding] = []
        for rule in self.rules:
            if vendor and not self._vendor_matches(rule, vendor):
                continue
            finding = self._evaluate_rule(rule, ir)
            findings.append(finding)
        return findings

    def _vendor_matches(self, rule: dict, vendor: str) -> bool:
        vendors = [v.lower() for v in rule.get("vendors", ["all"])]
        return "all" in vendors or vendor.lower() in vendors

    def _evaluate_rule(self, rule: dict, ir: dict) -> Finding:
        rule_id = rule["rule_id"]
        match_spec = rule["match"]

        # Manual checks are never automated — always emit a manual_check finding
        if match_spec.get("type") == "manual":
            return Finding(
                rule_id=rule_id,
                name=rule["name"],
                severity=rule.get("severity", "info"),
                status="manual_check",
                description=rule.get("description", ""),
                remediation=rule.get("remediation", ""),
                frameworks=rule.get("frameworks", {}),
                details=match_spec.get("guidance", ""),
                source_rule_file=rule.get("_source_file", ""),
            )

        # not_applicable_when: if the condition is met, skip the rule as not applicable
        na_spec = rule.get("not_applicable_when")
        if na_spec:
            try:
                na_passed, na_detail, _, _ = self._apply_match(na_spec, ir)
                if na_passed:
                    return Finding(
                        rule_id=rule_id,
                        name=rule["name"],
                        severity=rule.get("severity", "info"),
                        status="not_applicable",
                        description=rule.get("description", ""),
                        remediation="",
                        frameworks=rule.get("frameworks", {}),
                        details=rule.get("not_applicable_reason", "Rule not applicable to this device/configuration."),
                        source_rule_file=rule.get("_source_file", ""),
                    )
            except Exception as exc:
                log.debug("Rule %s not_applicable_when raised exception: %s", rule_id, exc)

        try:
            status, details, affected_paths, affected_values = self._apply_match(match_spec, ir)
        except Exception as exc:
            log.debug("Rule %s raised exception: %s", rule_id, exc, exc_info=True)
            return Finding(
                rule_id=rule_id,
                name=rule["name"],
                severity=rule["severity"],
                status="error",
                description=rule.get("description", ""),
                remediation=rule.get("remediation", ""),
                frameworks=rule.get("frameworks", {}),
                details=f"Evaluation error: {exc}",
                source_rule_file=rule.get("_source_file", ""),
            )

        return Finding(
            rule_id=rule_id,
            name=rule["name"],
            severity=rule["severity"],
            status="pass" if status else "fail",
            description=rule.get("description", ""),
            remediation=rule.get("remediation", "") if not status else "",
            frameworks=rule.get("frameworks", {}),
            affected_paths=affected_paths,
            affected_values=affected_values,
            details=details,
            source_rule_file=rule.get("_source_file", ""),
        )

    def _apply_match(self, match: dict, ir: dict) -> tuple[bool, str, list[str], list[Any]]:
        """Evaluate a match block. Returns (passed, detail, affected_paths, affected_values)."""
        match_type = match.get("type", "condition")

        if match_type == "condition":
            path = match.get("path", "")
            value = resolve_path(ir, path)
            condition = match.get("condition", {})
            passed, detail = self._cond_checker.check(condition, value, path)
            affected_values = [value] if not passed else []
            return passed, detail, [path] if not passed else [], affected_values

        elif match_type == "all_of":
            # All sub-checks must pass
            checks = match.get("checks", [])
            failed_paths: list[str] = []
            failed_vals: list[Any] = []
            details: list[str] = []
            for check in checks:
                p, d, ap, av = self._apply_match(check, ir)
                if not p:
                    failed_paths.extend(ap)
                    failed_vals.extend(av)
                    details.append(d)
            passed = len(failed_paths) == 0
            return passed, "; ".join(details) if details else "all checks passed", failed_paths, failed_vals

        elif match_type == "any_of":
            # At least one sub-check must pass
            checks = match.get("checks", [])
            passed_any = False
            all_details: list[str] = []
            for check in checks:
                p, d, _, _ = self._apply_match(check, ir)
                if p:
                    passed_any = True
                    break
                all_details.append(d)
            return passed_any, "none of the checks passed: " + "; ".join(all_details) if not passed_any else "at least one check passed", [], []

        elif match_type == "none_of":
            # No sub-check must pass
            checks = match.get("checks", [])
            failing: list[str] = []
            for check in checks:
                p, d, ap, av = self._apply_match(check, ir)
                if p:
                    failing.append(d)
            passed = len(failing) == 0
            return passed, "unexpected passing checks: " + "; ".join(failing) if not passed else "none matched (good)", [], []

        elif match_type in ("exists_where", "not_exists_where"):
            list_path = match.get("path", "")
            items = resolve_path(ir, list_path) or []
            where = match.get("where", {})

            if not isinstance(items, list):
                # Path didn't resolve to a list — nothing to find
                passed = match_type == "not_exists_where"
                return passed, "path did not resolve to a list", [], []

            matched_items: list[tuple[int, dict]] = []
            for idx, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                item_match = True
                for field_key, sub_cond in where.items():
                    # Support dotted paths within the item (e.g. "phase1.encryption")
                    if "." in field_key:
                        field_val = _resolve(item, _split_path(field_key))
                    else:
                        field_val = item.get(field_key)
                    cond_passed, _ = self._cond_checker.check(sub_cond, field_val, field_key)
                    if not cond_passed:
                        item_match = False
                        break
                if item_match:
                    matched_items.append((idx, item))

            found = len(matched_items) > 0
            if match_type == "not_exists_where":
                passed = not found
                if not passed:
                    names = [str(item.get("name", idx)) for idx, item in matched_items[:5]]
                    detail = f"Found {len(matched_items)} offending item(s): {', '.join(names)}"
                    ap = [f"{list_path}[{item.get('name', idx)}]" for idx, item in matched_items[:5]]
                    av: list[Any] = [item.get("name", item) for _, item in matched_items[:5]]
                else:
                    detail = "no matching items found (good)"
                    ap, av = [], []
            else:  # exists_where
                passed = found
                if passed:
                    names = [str(item.get("name", idx)) for idx, item in matched_items[:5]]
                    detail = f"Found {len(matched_items)} matching item(s): {', '.join(names)}"
                    ap, av = [], []
                else:
                    detail = "no items matched where conditions"
                    ap, av = [], []
            return passed, detail, ap, av

        elif match_type == "foreach":
            # Evaluate checks against each item in a list path
            list_path = match.get("path", "")
            items = resolve_path(ir, list_path) or []
            checks = match.get("checks", [])
            filter_cond = match.get("filter")
            fail_mode = match.get("fail_on", "any")  # "any" or "all"

            if not isinstance(items, list):
                return True, "no items to check", [], []

            failures: list[tuple[str, str, Any]] = []
            for idx, item in enumerate(items):
                # Apply filter if specified
                if filter_cond:
                    filter_val = item.get(filter_cond.get("field", "")) if isinstance(item, dict) else item
                    filter_passed, _ = self._cond_checker.check(filter_cond.get("condition", {}), filter_val, "")
                    if not filter_passed:
                        continue

                for check in checks:
                    # Resolve relative paths within item context
                    item_match = dict(check)
                    relative_path = check.get("path", "")
                    # Resolve relative path against item dict
                    if isinstance(item, dict):
                        value = _resolve(item, _split_path(relative_path)) if relative_path else item
                    else:
                        value = item
                    condition = check.get("condition", {})
                    passed, detail = self._cond_checker.check(condition, value, relative_path)
                    if not passed:
                        name_val = item.get("name", idx) if isinstance(item, dict) else idx
                        failures.append((f"{list_path}[{name_val}].{relative_path}", detail, value))

            if fail_mode == "any":
                overall_passed = len(failures) == 0
            else:
                overall_passed = len(failures) < len(items)

            detail_str = "; ".join(f"{p}: {d}" for p, d, _ in failures[:5])
            if len(failures) > 5:
                detail_str += f" ... and {len(failures) - 5} more"

            return overall_passed, detail_str if failures else "all items passed", [f for f, _, _ in failures], [v for _, _, v in failures]

        else:
            return False, f"unknown match type: {match_type!r}", [], []


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

def build_report(
    ir: dict,
    findings: list[Finding],
    framework_filter: str | None = None,
) -> dict:
    """Assemble a structured JSON report from findings."""
    vendor = ir.get("meta", {}).get("vendor", "unknown")
    hostname = ir.get("meta", {}).get("hostname", "unknown")

    total = len(findings)
    by_status: dict[str, int] = {"pass": 0, "fail": 0, "error": 0, "not_applicable": 0, "manual_check": 0}
    by_severity: dict[str, dict] = {}

    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        if f.status == "manual_check":
            continue  # manual checks are not included in severity/compliance scoring
        if f.status == "fail":
            by_severity.setdefault(f.severity, {"pass": 0, "fail": 0})
            by_severity[f.severity]["fail"] += 1
        elif f.status == "pass":
            by_severity.setdefault(f.severity, {"pass": 0, "fail": 0})
            by_severity[f.severity]["pass"] += 1

    # Per-framework compliance scores (manual checks excluded)
    framework_scores: dict[str, dict] = {}
    for f in findings:
        if f.status == "manual_check":
            continue
        for fw, controls in f.frameworks.items():
            if framework_filter and fw.lower() != framework_filter.lower():
                continue
            framework_scores.setdefault(fw, {"pass": 0, "fail": 0, "controls": set()})
            if isinstance(controls, list):
                framework_scores[fw]["controls"].update(controls)
            elif isinstance(controls, str):
                framework_scores[fw]["controls"].add(controls)
            if f.status == "pass":
                framework_scores[fw]["pass"] += 1
            elif f.status == "fail":
                framework_scores[fw]["fail"] += 1

    compliance_scores: dict[str, dict] = {}
    for fw, data in framework_scores.items():
        total_fw = data["pass"] + data["fail"]
        score = round(data["pass"] / total_fw * 100, 1) if total_fw > 0 else 0
        compliance_scores[fw] = {
            "score_percent": score,
            "pass": data["pass"],
            "fail": data["fail"],
            "controls_tested": sorted(data["controls"]),
        }

    from fireaudit.engine.scoring import compute_posture_score
    posture = compute_posture_score(findings)

    return {
        "report_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "posture_score": posture,
        "device": {
            "vendor": vendor,
            "hostname": hostname,
            "model": ir.get("meta", {}).get("model"),
            "firmware_version": ir.get("meta", {}).get("firmware_version"),
            "source_file": ir.get("meta", {}).get("source_file"),
        },
        "summary": {
            "total_rules": total,
            **by_status,
            "by_severity": by_severity,
        },
        "compliance_scores": compliance_scores,
        "findings": [f.to_dict() for f in findings],
    }
