#!/usr/bin/env python3
"""
example_config.py — copy this to config.py and fill in your values.

    cp example_config.py config.py
    chmod 600 config.py          # optional but recommended
    $EDITOR config.py

config.py is gitignored. This file is committed so new users have a starting
point.
"""

# ... [same structure as config.py above] ...

# The only differences are the defaults:

BRIDGE_ENABLED = False          # off by default — user opts in
BRIDGE_URL     = "https://your-bridge.example/api.php"
BRIDGE_KEY     = "CHANGE_ME"

OAST_DOMAIN = "your-oob-domain.example"
OAST_KEY    = ""
OAST_MODE   = "disabled"        # off by default — user opts in

ACTIVE_PLATFORM = "hackerone"   # user chooses
PLATFORM_HEADERS = {
    "hackerone": {"User-Agent": "argus/1.0"},  # fill in your own
    # ...
}
TEST_ACCOUNTS = {}              # user fills in — tool refuses if empty
SYNC_TO_DB = False              # off by default
