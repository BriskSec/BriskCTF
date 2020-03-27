mkdir -p tools/general
cd tools/general

    banner "tools - https://github.com/drwetter/testssl.sh.git"
    git clone --depth=1 --recursive https://github.com/drwetter/testssl.sh.git
    
    banner "tools - https://github.com/ayomawdb/AutoRecon.git"
    git clone --depth=1 --recursive https://github.com/ayomawdb/AutoRecon.git
    sudo apt install python3-pip
    sudo pip3 install toml
    
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

    banner "tools - https://github.com/Veil-Framework/Veil-Evasion.git"
    git clone --depth=1 --recursive https://github.com/Veil-Framework/Veil-Evasion.git
    cd Veil-Evasion/setup
    setup.sh -c
    cd ../..

    banner "tools - https://github.com/nullsecuritynet/tools.git"
    git clone --depth=1 --recursive https://github.com/nullsecuritynet/tools.git nullsecuritynet-tools

    banner "tools - Hyperion from nullsecuritynet-tools"
    wget https://github.com/nullsecuritynet/tools/raw/master/binary/hyperion/release/Hyperion-2.2.zip
    unzip Hyperion-2.2.zip
    i686-w64-mingw32-c++ Hyperion-2.2/Src/Crypter/*.cpp -o Hyperion-2.2/hyperion.exe

    # https://github.com/upx/upx/releases

    banner "tools - https://github.com/1N3/Sn1per.git"
    git clone --depth=1 --recursive https://github.com/1N3/Sn1per.git

    banner "tools - DDOS Amplification - https://github.com/S4kur4/Saddam-new.git"
    git clone --depth=1 --recursive https://github.com/S4kur4/Saddam-new.git

    banner "tools - fsociety Hacking Tools Pack - https://github.com/Manisso/fsociety.git"
    git clone --depth=1 --recursive https://github.com/Manisso/fsociety.git

    banner "tools - onetwopunch - Nmap + unicornscan - https://github.com/Manisso/fsociety.git"
    wget -N https://raw.githubusercontent.com/superkojiman/onetwopunch/master/onetwopunch.sh

    banner "tools - tko-subs - Subdomain takeover - https://github.com/anshumanbh/tko-subs"
    # go get github.com/anshumanbh/tko-subs
    docker build -t tko-subs https://github.com/anshumanbh/tko-subs.git
    # docker run tko-subs/
    # https://github.com/EdOverflow/can-i-take-over-xyz

    banner "tools - Amass - network mapping of attack surfaces - https://github.com/OWASP/Amass.git"
    docker build -t amass https://github.com/OWASP/Amass.git
    # docker run -v OUTPUT_DIR_PATH:/.config/amass/ amass enum --list

    banner "tools - Subfinder - subdomain discovery - https://github.com/projectdiscovery/subfinder.git"
    docker build -t subfinder https://github.com/projectdiscovery/subfinder.git
    mkdir $HOME/.config/subfinder
    # cp config.yaml $HOME/.config/subfinder/config.yaml
    # docker run -v $HOME/.config/subfinder:/root/.config/subfinder -it ice3man/subfinder -d freelancer.com

    # dnSpy is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available. Main features:
    #git clone --depth=1 --recursive https://github.com/0xd4d/dnSpy.git
    #cd dnSpy
    # or dotnet build
    #./build.ps1 -NoMsbuild

    # https://opendata.rapid7.com/

cd ..


