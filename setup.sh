#!/bin/bash

bash _setup/clean.sh
# Done first (update pkg lists, etc.)
bash _setup/setup_env.sh
# Payloaf, fuzzing, and other lists
bash _setup/setup_lists.sh
# Exploits usable to gain initial foothold
bash _setup/setup_exploits_*.sh
# Exploits usable in privilege escalation
bash _setup/setup_prevesc_*.sh
# Different attack payloads (setup_payloads.sh will be called internally)
bash _setup/setup_payloads_*.sh
# Scripts that need to be accessed from victim host
bash _setup/setup_scripts_*.sh
# DIfferent tools used locally (in attacker's machine)
bash _setup/setup_tools.sh
bash _setup/setup_tools_*.sh
