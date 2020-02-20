mkdir -p tools
cd tools

    banner "tools - https://github.com/drwetter/testssl.sh.git"
    git clone --depth=1 --recursive https://github.com/drwetter/testssl.sh.git
    
    banner "tools - https://github.com/ayomawdb/AutoRecon.git"
    git clone --depth=1 --recursive https://github.com/ayomawdb/AutoRecon.git
    pip install toml
    
    banner "tools - https://github.com/Ganapati/RsaCtfTool.git"
    git clone --depth=1 --recursive https://github.com/Ganapati/RsaCtfTool.git
    
    banner "tools - https://github.com/GDSSecurity/PadBuster.git"
    git clone --depth=1 --recursive https://github.com/GDSSecurity/PadBuster.git
    
    banner "tools - https://github.com/Va5c0/Steghide-Brute-Force-Tool.git"
    git clone --depth=1 --recursive https://github.com/Va5c0/Steghide-Brute-Force-Tool.git

    banner "tools - https://github.com/trinitronx/vncpasswd.py.git"
    git clone --depth=1 --recursive https://github.com/trinitronx/vncpasswd.py.git

    banner "tools - https://github.com/jeroennijhof/vncpwd.git"
    git clone --depth=1 --recursive https://github.com/jeroennijhof/vncpwd.git

    banner "tools - https://github.com/trailofbits/protofuzz.git"
    git clone --depth=1 --recursive https://github.com/trailofbits/protofuzz.git

    banner "tools - https://github.com/lanjelot/patator.git"
    git clone --depth=1 --recursive https://github.com/lanjelot/patator.git

    # https://alamot.github.io/legacy_writeup/
    banner "tools - https://github.com/mdiazcl/fuzzbunch-debian.git"
    git clone --depth=1 --recursive https://github.com/mdiazcl/fuzzbunch-debian.git
    banner "tools - https://github.com/peterpt/fuzzbunch.git"
    git clone --depth=1 --recursive https://github.com/peterpt/fuzzbunch.git

    if [ ! -f vncpwd.exe ]; then
        banner "tools - http://aluigi.altervista.org/pwdrec/vncpwd.zip"
        wget http://aluigi.altervista.org/pwdrec/vncpwd.zip
        unzip vncpwd.zip -d tmp_vncpwd
        cp tmp_vncpwd/vncpwd.exe .
        rm -rf tmp_vncpwd
        rm vncpwd.zip
    fi

    banner "tools - impacket smbserver.py"
    wget -N https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbserver.py

    banner "tools - https://github.com/pentestmonkey/smtp-user-enum"
    wget -N https://raw.githubusercontent.com/pentestmonkey/smtp-user-enum/master/smtp-user-enum.pl

    banner "tools - gpp-decrypt2.rb"
    wget -N https://raw.githubusercontent.com/weaknetlabs/Penetration-Testing-Grimoire/master/Tools/gpp-decrypt2.rb

    banner "tools - https://github.com/BC-SECURITY/Empire.git"
    git clone --depth=1 --recursive https://github.com/BC-SECURITY/Empire.git

    banner "tools - https://github.com/cobbr/Covenant.git"
    git clone --depth=1 --recursive https://github.com/cobbr/Covenant.git

    banner "tools - https://github.com/mubix/pykek.git"
    git clone --depth=1 --recursive https://github.com/mubix/pykek.git

    if [ ! -d fuzzowski ]; then
        banner "tools - Fuzzowski - Network Protocol Fuzzer (LPD/IPP/BACnet/Modbus/...) - https://github.com/nccgroup/fuzzowski.git"
        git clone --depth=1 --recursive https://github.com/nccgroup/fuzzowski.git
        cd fuzzowski
        virtualenv venv -p python3
        source venv/bin/activate
        pip install -r requirements.txt
        python3 -m fuzzowski --help 
        deactivate
        cd ..
    fi
  
cd ..


