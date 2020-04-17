mkdir -p tools/windows
cd tools/windows
  
    banner "tools_windows - https://github.com/bitsadmin/wesng.git"
    git clone --depth=1 --recursive https://github.com/bitsadmin/wesng.git

    banner "tools_windows - https://github.com/deepzec/Bad-Pdf.git"
    git clone --depth=1 --recursive https://github.com/deepzec/Bad-Pdf.git

    banner "tools_windows - https://bitbucket.org/grimhacker/gpppfinder.git"
    git clone --depth=1 --recursive https://bitbucket.org/grimhacker/gpppfinder.git

    banner "tools_windows - https://github.com/Kevin-Robertson/Inveigh.git"
    git clone --depth=1 --recursive https://github.com/Kevin-Robertson/Inveigh.git

    if [ ! -d mimikatz ]; then
        banner "tools_windows - https://github.com/gentilkiwi/mimikatz"
        wget -N -O mimikatz_trunk.zip https://github.com`curl https://github.com/gentilkiwi/mimikatz/releases | grep "download" | grep "zip" | head -1 | cut -d "\"" -f2`
        #Following call fails sometimes due to API rate limiting. Hence reading HTML. 
        #curl -s https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest \
        # | grep "zipball_url.*zip" \
        # | cut -d : -f 2,3 \
        # | tr -d \" \
        # | tr -d , \
        # | wget -qi -O mimikatz_trunk.zip -
        unzip -d mimikatz mimikatz_trunk.zip 
        rm mimikatz_trunk.zip
    fi

    banner "tools_windows - PowerZure - PowerShell script written to assist in assessing Azure security - https://github.com/hausec/PowerZure"
    # https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a
    wget https://raw.githubusercontent.com/hausec/PowerZure/master/PowerZure.ps1

    banner "tools_windows - https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git"
    git clone --depth=1 --recursive https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git

    banner "tools_windows - Updating https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git"
    cd Windows-Exploit-Suggester
    chmod +x windows-exploit-suggester.py
    ./windows-exploit-suggester.py --update
    cd ..

    banner "tools_windows - https://awarenetwork.org/home/rattle/source/python/exe2bat.py"
    wget -N https://awarenetwork.org/home/rattle/source/python/exe2bat.py

    banner "tools_windows - https://github.com/yanncam/exe2powershell"
    wget -N https://github.com/yanncam/exe2powershell/raw/master/bin/exe2bat.exe
    wget -N https://github.com/yanncam/exe2powershell/blob/master/bin/exe2powershell.exe
    wget -N https://github.com/yanncam/exe2powershell/blob/master/bin/upx.exe

    banner "tools - Windows SMB Password Dictionary Attack Tool - https://github.com/qashqao/acccheck"
    wget -N https://raw.githubusercontent.com/qashqao/acccheck/master/
    
    banner "tools - Evil-WinRM - https://github.com/Hackplayers/evil-winrm.git"
    #git clone --depth=1 --recursive https://github.com/Hackplayers/evil-winrm.git
    sudo gem install evil-winrm

    git clone  --depth=1 --recursive https://github.com/SecureAuthCorp/impacket.git
    cd impacket/
    pip2 install .
    cd ..

    sudo apt install --no-upgrade amap

    git clone  --depth=1 --recursive https://github.com/ropnop/windapsearch.git

    # RDP bruteforce
    sudo apt install --no-upgrade crowbar

    #https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1
    #https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1

    # SharpExec is an offensive security C# tool designed to aid with lateral movement.
    # -WMIExec - Semi-Interactive shell that runs as the user. Best described as a less mature version of Impacket's wmiexec.py tool.
    # -SMBExec - Semi-Interactive shell that runs as NT Authority\System. Best described as a less mature version of Impacket's smbexec.py tool.
    # -PSExec (like functionality) - Gives the operator the ability to execute remote commands as NT Authority\System or upload a file and execute it with or without arguments as NT Authority\System.
    # -WMI - Gives the operator the ability to execute remote commands as the user or upload a file and execute it with or without arguments as the user.
    # https://github.com/anthemtotheego/SharpExec.git
    wget -N https://github.com/anthemtotheego/SharpExec/raw/master/CompiledBinaries/SharpExec_x64.exe
    wget -N https://github.com/anthemtotheego/SharpExec/raw/master/CompiledBinaries/SharpExec_x86.exe

cd ../..
