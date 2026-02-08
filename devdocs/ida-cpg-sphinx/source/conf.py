project = "IDA MicroCode CPG & CWE Scanner"
author = "AIDA"

extensions = [
    "myst_parser",
]

source_suffix = {
    ".md": "markdown",
}

master_doc = "index"
language = "zh_CN"

exclude_patterns = [
    "_build",
]

myst_heading_anchors = 3
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "tasklist",
]

html_theme = "alabaster"

