#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
msynth MBA Simplification and SMT Equivalence Worker.

Reuses Python standard library ast module to safely parse mathematical and
bitwise MBA expressions into Miasm expressions without eval.
Simplifies expressions using msynth (mrphrazer/msynth) Synthesizer or
bundled verified Simplifier oracle, and formally verifies semantic equivalence
with the Z3 SMT solver over bitvectors.
"""

from __future__ import annotations

import sys
import os
import ast
import json
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================================
# Safe AST Visitor (No eval, transforms Python AST into Miasm Expr)
# ============================================================================

def parse_and_convert_to_miasm(expr_str: str, bit_width: int, miasm_mod):
    ExprId = miasm_mod.expression.expression.ExprId
    ExprInt = miasm_mod.expression.expression.ExprInt
    ExprOp = miasm_mod.expression.expression.ExprOp
    ExprSlice = miasm_mod.expression.expression.ExprSlice

    class SafeMiasmConverter(ast.NodeVisitor):
        def __init__(self, bw: int):
            self.bit_width = bw
            self.variables: Set[str] = set()

        def convert(self, s: str):
            try:
                tree = ast.parse(s.strip(), mode="eval")
            except SyntaxError as e:
                raise ValueError(f"Syntax error in expression: {e}")
            return self.visit(tree.body)

        def visit_Constant(self, node: ast.Constant):
            if isinstance(node.value, int):
                return ExprInt(node.value, self.bit_width)
            raise ValueError(f"Unsupported constant type: {type(node.value).__name__}")

        def visit_Name(self, node: ast.Name):
            self.variables.add(node.id)
            return ExprId(node.id, self.bit_width)

        def visit_UnaryOp(self, node: ast.UnaryOp):
            operand = self.visit(node.operand)
            if isinstance(node.op, ast.Invert):
                return ExprOp("~", operand)
            if isinstance(node.op, ast.USub):
                return ExprOp("-", operand)
            if isinstance(node.op, ast.UAdd):
                return operand
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")

        def visit_BinOp(self, node: ast.BinOp):
            left = self.visit(node.left)
            right = self.visit(node.right)
            op_map = {
                ast.Add: "+",
                ast.Sub: "-",
                ast.Mult: "*",
                ast.BitAnd: "&",
                ast.BitOr: "|",
                ast.BitXor: "^",
                ast.LShift: "<<",
                ast.RShift: ">>",
            }
            op_type = type(node.op)
            if op_type in op_map:
                return ExprOp(op_map[op_type], left, right)
            raise ValueError(f"Unsupported binary operator: {op_type.__name__}")

        def visit_Subscript(self, node: ast.Subscript):
            value = self.visit(node.value)
            if isinstance(node.slice, ast.Slice):
                lower = node.slice.lower.value if isinstance(node.slice.lower, ast.Constant) else 0
                upper = node.slice.upper.value if isinstance(node.slice.upper, ast.Constant) else self.bit_width
                return ExprSlice(value, int(lower), int(upper))
            raise ValueError("Unsupported subscript slice")

        def generic_visit(self, node):
            raise ValueError(
                f"Disallowed expression syntax: {type(node).__name__}. "
                "Only arithmetic, bitwise operators, constants, and variables are permitted."
            )

    converter = SafeMiasmConverter(bit_width)
    miasm_expr = converter.convert(expr_str)
    return miasm_expr, converter.variables


def count_miasm_nodes(expr) -> int:
    if expr.is_int() or expr.is_id():
        return 1
    if expr.is_op():
        return 1 + sum(count_miasm_nodes(a) for a in expr.args)
    if expr.is_slice():
        return 1 + count_miasm_nodes(expr.arg)
    return 1


# ============================================================================
# Z3 SMT Equivalence Prover
# ============================================================================

def verify_smt_equivalence(orig_expr, simp_expr, bit_width: int, var_names: Set[str]) -> Dict[str, Any]:
    try:
        import z3

        z3_vars = {}

        def miasm_to_z3(expr):
            sz = int(getattr(expr, "size", bit_width))
            if expr.is_int():
                return z3.BitVecVal(int(expr.arg), sz)
            if expr.is_id():
                name = str(expr.name)
                key = (name, sz)
                if key not in z3_vars:
                    z3_vars[key] = z3.BitVec(name, sz)
                return z3_vars[key]
            if expr.is_op():
                op = str(expr.op)
                args = [miasm_to_z3(a) for a in expr.args]
                if op == "+":
                    res = args[0]
                    for a in args[1:]:
                        res = res + a
                    return res
                if op == "-":
                    if len(args) == 1:
                        return -args[0]
                    return args[0] - args[1]
                if op == "*":
                    return args[0] * args[1]
                if op == "&":
                    return args[0] & args[1]
                if op == "|":
                    return args[0] | args[1]
                if op == "^":
                    return args[0] ^ args[1]
                if op == "~":
                    return ~args[0]
                if op == "<<":
                    l, r = args[0], args[1]
                    if l.size() != r.size():
                        r = z3.ZeroExt(l.size() - r.size(), r) if l.size() > r.size() else z3.Extract(l.size() - 1, 0, r)
                    return l << r
                if op == ">>":
                    l, r = args[0], args[1]
                    if l.size() != r.size():
                        r = z3.ZeroExt(l.size() - r.size(), r) if l.size() > r.size() else z3.Extract(l.size() - 1, 0, r)
                    return z3.LShR(l, r)
                raise ValueError(f"Unknown op: {op}")
            if expr.is_slice():
                sub = miasm_to_z3(expr.arg)
                return z3.Extract(int(expr.stop) - 1, int(expr.start), sub)
            raise ValueError(f"Unknown Miasm expr: {expr}")

        orig_z3 = miasm_to_z3(orig_expr)
        simp_z3 = miasm_to_z3(simp_expr)
        solver = z3.Solver()
        solver.set("timeout", 10000)  # 10s timeout
        solver.add(orig_z3 != simp_z3)
        check_res = solver.check()

        if check_res == z3.unsat:
            return {
                "verified": True,
                "equivalent": True,
                "solver": "z3",
                "counterexample": None,
            }
        elif check_res == z3.sat:
            m = solver.model()
            cex = {str(d): str(m[d]) for d in m.decls()}
            return {
                "verified": True,
                "equivalent": False,
                "solver": "z3",
                "counterexample": cex,
            }
        else:
            return {
                "verified": False,
                "equivalent": None,
                "solver": "z3",
                "reason": str(solver.reason_unknown()),
            }
    except ImportError:
        return {
            "verified": False,
            "equivalent": None,
            "solver": "none",
            "reason": "z3-solver not installed",
        }
    except Exception as e:
        return {
            "verified": False,
            "equivalent": None,
            "solver": "error",
            "reason": str(e),
        }


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            sys.stdout.write(json.dumps({"status": "error", "error": "Empty input"}))
            return

        req = json.loads(raw_input)
        expr_str = req.get("expression")
        if not expr_str:
            sys.stdout.write(json.dumps({"status": "error", "error": "Missing 'expression' field"}))
            return

        bit_width = int(req.get("bit_width", 32))
        mode = req.get("mode", "ast")
        verify_smt = bool(req.get("verify_smt", True))

        # 1. Require actual msynth and miasm upstream engines (Fail closed if missing)
        try:
            import miasm
            from miasm.expression.expression import ExprId, ExprInt, ExprOp, ExprSlice
            import msynth
            from msynth import Simplifier, Synthesizer
        except ImportError as e:
            sys.stdout.write(json.dumps({
                "status": "missing_dependency",
                "error": f"Required msynth engine dependency missing: {e}. Please run 'reverse setup reverse msynth --execute'.",
                "missing": [str(e)]
            }))
            return

        # 2. Parse expression safely using Python AST visitor (no eval)
        orig_miasm, var_names = parse_and_convert_to_miasm(expr_str, bit_width, miasm)

        # 3. Locate verified bundled oracle only (never arbitrary user pickle loads)
        msynth_dir = os.path.dirname(os.path.abspath(msynth.__file__))
        msynth_root = os.path.dirname(msynth_dir)
        verified_oracles = [
            os.path.join(msynth_root, "src", "oracle.pickle"),
            os.path.join(msynth_root, "oracle.pickle"),
            os.path.join(msynth_root, "oracle.db"),
            os.path.join(msynth_root, "database", "oracle.pickle"),
            os.path.join(msynth_root, "database", "oracle.db"),
        ]

        TRUSTED_ORACLE_SHA256 = "176f2bb6420db7a8d171535d9cc45b0b9d7fea95573d9f9d8a7a27ae057ebdc0"
        bundled_oracle = None
        for cand in verified_oracles:
            if os.path.isfile(cand):
                try:
                    import hashlib
                    with open(cand, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    if file_hash == TRUSTED_ORACLE_SHA256:
                        bundled_oracle = cand
                        break
                except Exception:
                    pass
        # 4. Execute msynth simplification
        simplified_miasm = None
        engine_used = "msynth_synthesizer"

        if mode == "ast" and bundled_oracle:
            simplifier = Simplifier(bundled_oracle)
            simplified_miasm = simplifier.simplify(orig_miasm)
            engine_used = "msynth_oracle"
        else:
            # Use msynth stochastic synthesizer with Smir
            synthesizer = Synthesizer()
            simplified_miasm = synthesizer.simplify(orig_miasm)
            engine_used = "msynth_synthesizer"

        if simplified_miasm is None:
            sys.stdout.write(json.dumps({
                "status": "error",
                "error": "msynth simplification returned None",
            }))
            return

        orig_nodes = count_miasm_nodes(orig_miasm)
        simp_nodes = count_miasm_nodes(simplified_miasm)
        eliminated = max(0, orig_nodes - simp_nodes)
        ratio = round(simp_nodes / orig_nodes, 4) if orig_nodes > 0 else 1.0

        # 5. Formally verify semantic equivalence with Z3
        smt_res = None
        if verify_smt:
            smt_res = verify_smt_equivalence(orig_miasm, simplified_miasm, bit_width, var_names)

        backend_info = {
            "engine": engine_used,
            "msynth_version": getattr(msynth, "__version__", "installed"),
            "miasm_version": getattr(miasm, "__version__", "installed"),
        }
        try:
            import z3
            backend_info["z3_version"] = getattr(z3, "__version__", None) or (
                z3.get_version_string() if hasattr(z3, "get_version_string") else "installed"
            )
        except ImportError:
            backend_info["z3_version"] = "not_installed"
        out = {
            "status": "ok",
            "original": str(orig_miasm),
            "simplified": str(simplified_miasm),
            "bit_width": bit_width,
            "variables": sorted(list(var_names)),
            "complexity_reduction": {
                "original_nodes": orig_nodes,
                "simplified_nodes": simp_nodes,
                "nodes_eliminated": eliminated,
                "reduction_ratio": ratio,
            },
            "smt_verification": smt_res,
            "backend": backend_info,
        }

        sys.stdout.write(json.dumps(out, indent=2))
    except Exception as e:
        sys.stdout.write(json.dumps({"status": "error", "error": str(e)}))


if __name__ == "__main__":
    main()
