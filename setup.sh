#!/bin/bash

bash _setup/clean.sh
read -n 1 -s -r -p "clean complete. Press any key to continue"
# Do environment changes firest (update pkg lists, etc.)
bash _setup/setup_env.sh
read -n 1 -s -r -p "setup_env complete. Press any key to continue"
# Payloaf, fuzzing, and other lists
bash _setup/setup_lists.sh
read -n 1 -s -r -p "setup_lists complete. Press any key to continue"
# Exploits usable to gain initial foothold
bash _setup/setup_exploits_*.sh
read -n 1 -s -r -p "setup_exploits_* complete. Press any key to continue"
# Different attack payloads (setup_payloads.sh will be called internally)
bash _setup/setup_payloads_*.sh
read -n 1 -s -r -p "setup_payloads_* complete. Press any key to continue"
# Scripts that need to be accessed from victim host
bash _setup/setup_scripts_*.sh
read -n 1 -s -r -p "setup_scripts_* complete. Press any key to continue"
# DIfferent tools used locally (in attacker's machine)
bash _setup/setup_tools.sh
read -n 1 -s -r -p "setup_tools complete. Press any key to continue"
bash _setup/setup_tools_*.sh
read -n 1 -s -r -p "setup_tools_* complete. Press any key to continue"
