mkdir public/tools_linux
cd public/tools_linux

    # Enum

    banner "shared_linux - https://github.com/diego-treitos/linux-smart-enumeration"
    wget -N https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh

    banner "shared_linux - https://github.com/rebootuser/LinEnum"
    wget -N https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

    banner "shared_linux - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
    wget -N https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/linPEAS/linpeas.sh

    banner "shared_linux - https://github.com/sleventyeleven/linuxprivchecker"
    wget -N https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py

    banner "shared_linux - https://github.com/Arr0way/linux-local-enumeration-script"
    wget -N https://raw.githubusercontent.com/Arr0way/linux-local-enumeration-script/master/linux-local-enum.sh

    if [ ! -f unix-privesc-check.sh ]; then
        banner "shared_linux - https://github.com/pentestmonkey/unix-privesc-check/tree/1_x"
        wget -N https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/1_x/unix-privesc-check
        mv unix-privesc-check unix-privesc-check.sh
    fi

    banner "shared_linux - https://github.com/pentestmonkey/unix-privesc-check (modular)"
    git clone --depth=1 --recursive https://github.com/pentestmonkey/unix-privesc-check.git

    if [ ! -f linux_security_test.sh ]; then
        banner "shared_linux - https://github.com/1N3/PrivEsc/blob/master/linux/scripts/linux_security_test"
        wget -N https://raw.githubusercontent.com/1N3/PrivEsc/master/linux/scripts/linux_security_test
        mv linux_security_test linux_security_test.sh
    fi

    banner "shared_linux - https://github.com/AlessandroZ/BeRoot.git (modular)"
    git clone --depth=1 --recursive https://github.com/AlessandroZ/BeRoot.git

    banner "shared_linux - checksec - check the properties of executables - https://github.com/slimm609/checksec.sh"
    wget -N https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec

    # Exploit Suggester

    banner "shared_linux - linux_kernel_exploiter - https://github.com/1N3/PrivEsc/tree/master/linux/scripts"
    wget -N https://raw.githubusercontent.com/1N3/PrivEsc/master/linux/scripts/linux_kernel_exploiter.pl

    banner "shared_linux - https://github.com/InteliSecureLabs/Linux_Exploit_Suggester"
    wget -N https://raw.githubusercontent.com/InteliSecureLabs/Linux_Exploit_Suggester/master/Linux_Exploit_Suggester.pl

    banner "shared_linux - https://github.com/jondonas/linux-exploit-suggester-2"
    wget -N https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl

    banner "shared_linux - https://github.com/mzet-/linux-exploit-suggester"
    wget -N https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

    # Other tools  

    rm -rf impacketbins
    mkdir impacketbins
    cd impacketbins
        path=`curl https://github.com/ropnop/impacket_static_binaries/releases | grep "/ropnop/impacket_static_binaries/releases/download/" | cut -d "\"" -f2 | grep "impacket_linux" | head -1`
        wget -nc "https://github.com/$path"
        tar -xvf impacket_linux_binaries.tar.gz
    cd ..

    rm -rf impacketbins_musl
    mkdir impacketbins_musl
    cd impacketbins_musl
        path=`curl https://github.com/ropnop/impacket_static_binaries/releases | grep "/ropnop/impacket_static_binaries/releases/download/" | cut -d "\"" -f2 | grep "impacket_musl" | head -1`
        wget -nc "https://github.com/$path"
        tar -xvf impacket_musl_binaries.tar.gz
    cd ..


    banner "shared_linux - pspy32 - Process Monitoring - https://github.com/DominicBreuker/pspy"
    wget -N https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy32
    wget -N https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy64
    wget -N https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy32s
    wget -N https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy64s

    if [ ! -d mimipenguin_2.0 ]; then
        banner "shared_linux - mimipenguin - mimikatz for linux - https://github.com/huntergregal/mimipenguin.git"
        wget https://github.com/huntergregal/mimipenguin/releases/download/2.0-release/mimipenguin_2.0-release.tar.gz
        tar -xvf mimipenguin_2.0-release.tar.gz
        mv mimipenguin_2.0-release mimipenguin_2.0
    fi

    sudo apt-get install netcat-traditional
    cp /usr/bin/nc.traditional nc
    
cd -
