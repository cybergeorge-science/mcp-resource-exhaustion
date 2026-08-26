"""
Locked experiment grid, shared by every vector's synthetic-sweep generator
(Phase 5: "step load magnitude ... concurrency levels [1, 8, 32, 128]").

`LOAD_LEVELS[vector]` maps the schema's abstract 1..5 `load_level` integer
to the vector-specific physical magnitude actually used (documented per
vector so Table 3 in the paper can be filled in directly). The real smoke
test for each vector uses `ANCHOR_LOAD_INDEX` and `ANCHOR_CONCURRENCY`
below -- i.e. it is one concrete cell of this grid, actually measured
rather than modeled.
"""

CONCURRENCY_LEVELS = [1, 8, 32, 128]
ANCHOR_CONCURRENCY = 8
N_REPS = 5

LOAD_LEVELS = {
    "v1_oversized_body": {"unit": "payload size (MB)", "values": [2, 5, 10, 20, 40]},
    "v2_init_flood": {"unit": "initialize requests / second (attempted)", "values": [10, 50, 200, 500, 1000]},
    "v3_unbounded_stdio": {"unit": "unterminated line length (MB)", "values": [1, 5, 20, 50, 100]},
    "v4_deep_json": {"unit": "JSON nesting depth", "values": [50, 200, 1000, 5000, 20000]},
    "v5_tool_flood": {"unit": "tools/call requests / second (attempted)", "values": [20, 100, 400, 1000, 2500]},
    "v6_slow_sse": {"unit": "server push volume attempted per slow connection (MB)", "values": [1, 5, 10, 20, 40]},
    "v7_redos": {"unit": "pathological input string length (chars, 'a'*n + '!' against ^(a+)+$)",
                 "values": [10, 18, 22, 26, 30]},
}

ANCHOR_LOAD_INDEX = {
    "v1_oversized_body": 3,   # 10 MB
    "v2_init_flood": 3,       # 200 req/s attempted
    "v3_unbounded_stdio": 3,  # 20 MB line
    "v4_deep_json": 3,        # depth 1000
    "v5_tool_flood": 3,       # 400 req/s attempted
    "v6_slow_sse": 3,         # 10 MB attempted push to one slow connection
    "v7_redos": 4,            # 26-char pathological input (values[3]=26)
}

# which (transport, sdk) combo actually got a REAL smoke test, per vector
REAL_ANCHOR = {
    "v1_oversized_body": {"transport": "http", "sdk": "python"},
    "v2_init_flood": {"transport": "http", "sdk": "python"},
    "v3_unbounded_stdio": {"transport": "stdio", "sdk": "typescript"},
    "v4_deep_json": {"transport": "http", "sdk": "python"},
    "v5_tool_flood": {"transport": "http", "sdk": "typescript"},
    "v6_slow_sse": {"transport": "sse", "sdk": "typescript"},
    "v7_redos": {"transport": "stdio", "sdk": "python"},
}

APPLICABLE_TRANSPORTS = {
    "v1_oversized_body": ["http", "stdio"],
    "v2_init_flood": ["http"],
    "v3_unbounded_stdio": ["stdio"],
    "v4_deep_json": ["http", "stdio"],
    "v5_tool_flood": ["http"],
    "v6_slow_sse": ["sse"],
    "v7_redos": ["http", "stdio"],
}

SDKS = ["python", "typescript"]
