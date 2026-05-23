"""Bundled example NDL files.

Use via importlib.resources, e.g.:

    import importlib.resources as pkg
    text = (pkg.files("sn_patterns_mcp.examples") / "apache_on_unix.ndl").read_text()

These are intentionally tiny fixtures so the headless smoke test in docs/DEMO.md
runs zero-config on a fresh `pip install sn-patterns-mcp`. They are not
production-grade patterns; they exercise common closures so the analyzer,
validator, and draft harness all have something real to chew on.
"""
