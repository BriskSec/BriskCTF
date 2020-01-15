#!/bin/bash

export ip_local='10.10.10.10'
export port_local=443
export port_remote=65300

bash _setup/clean.sh
read -n 1 -s -r -p "clean complete. Press any key to continue"
echo ""
# Do environment changes firest (update pkg lists, etc.)
bash _setup/setup_env.sh
read -n 1 -s -r -p "setup_env complete. Press any key to continue"
echo ""
# Payloaf, fuzzing, and other lists
bash _setup/setup_lists.sh
read -n 1 -s -r -p "setup_lists complete. Press any key to continue"
echo ""
# Exploits usable to gain initial foothold
for i in _setup/setup_exploits_*.sh; do bash $i; done
read -n 1 -s -r -p "setup_exploits_* complete. Press any key to continue"
echo ""
# Different attack payloads (setup_payloads.sh will be called internally)
for i in _setup/setup_payloads_*.sh; do bash $i; done
read -n 1 -s -r -p "setup_payloads_* complete. Press any key to continue"
echo ""
# Scripts that need to be accessed from victim host
for i in _setup/setup_scripts_*.sh; do bash $i; done
read -n 1 -s -r -p "setup_scripts_* complete. Press any key to continue"
echo ""
# DIfferent tools used locally (in attacker's machine)
bash _setup/setup_tools.sh
read -n 1 -s -r -p "setup_tools complete. Press any key to continue"
echo ""
for i in _setup/setup_tools_*.sh; do bash $i; done
read -n 1 -s -r -p "setup_tools_* complete. Press any key to continue"
echo ""
