#!/bin/bash

if [ $# -lt 3 ]
  then
    echo "Usage ./setup.sh source_ip source_port remote_port [use_recommended_defaults]"
    echo "  source_ip   - IP address or the interface-name (ex: tun0) of the attacker machine"
    echo "                This is mostly used as the target IP of reverse-tcp connections"
    echo "  source_port - Port to listen on the attacker machine"
    echo "                This is mostly used as the destination port of reverse-tcp connections"
    echo "  remote_port - Port to open on the target machine"
    echo "                This is mostly used as the source port of bind-tcp connections"
    echo "  use_recommended_defaults - Ask less questions and use recommended defaults instead"
    exit
fi

# Source information (source port is not taken from interface list, to re-use this in pivoting situations)
if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  source_ip=$1
else
  source_ip="$(ip addr show | grep $1 |grep -o 'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | grep -o '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*')"
fi
source_port=$2
remote_port=$3

# Ensure port exists
if [ $source_port -gt 65535 ]
then
  echo "Invalid source port!"
  exit
fi
# Ensure port exists
if [ $remote_port -gt 65535 ]
then
  echo "Invalid remote port!"
  exit
fi

useRecommended = false
if [ "$4" = true ]; then
  useRecommended = true
fi
export source_ip
export source_port
export remote_port
export useRecommended

confirm() {
    if $useRecommended; then
        false
    else
        # call with a prompt string or use a default
        read -r -p "${1:-Are you sure? [y/N]} " response
        case "$response" in
            [yY][eE][sS]|[yY]) 
                true
                ;;
            *)
                false
                ;;
        esac
    fi
}
export -f confirm

header() {
    echo ""
    echo ""
    echo "=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*"
    echo "** $1"
    echo "=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*"
}
export -f header

banner() {
    echo ""
    echo ""
    echo "============================================"
    echo "-- $1"
    echo "============================================"
}
export -f banner


header "Cleanup tasks"
bash _setup/clean.sh

header "Environment setup"
bash _setup/setup_env.sh

header "Lists - Payloaf, fuzzing, and other lists"
bash _setup/setup_lists.sh

header "Exploits - Exploits usable to gain initial foothold & prevesc"
for i in _setup/setup_exploits_*.sh; do bash $i; done

header "Tools - Different tools used locally (in attacker's machine)"
bash _setup/setup_tools.sh
for i in _setup/setup_tools_*.sh; do bash $i; done

header "Payloads - Different attack payloads"
for i in _setup/setup_payloads_*.sh; do bash $i; done

header "Public - Scripts or tools that need to be accessed from victim host"
for i in _setup/setup_public_*.sh; do bash $i; done

