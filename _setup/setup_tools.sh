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

  if [ ! -d debian-ssh-master ]; then
    banner "tools - https://github.com/g0tmi1k/debian-ssh"
    axel https://github.com/g0tmi1k/debian-ssh/archive/master.zip
    unzip debian-ssh-master.zip
    cd debian-ssh-master/common_keys
    banner "tools - extracting common_keys - https://github.com/g0tmi1k/debian-ssh"
    tar vjxf debian_ssh_dsa_1024_x86.tar.bz2
    tar vjxf debian_ssh_rsa_2048_x86.tar.bz2
    cd -
    cd debian-ssh-master/uncommon_keys
    banner "tools - extracting uncommon_keys - https://github.com/g0tmi1k/debian-ssh"
    tar vjxf debian_ssh_rsa_1023_x86.tar.bz2
    tar vjxf debian_ssh_rsa_1024_x86.tar.bz2
    tar vjxf debian_ssh_rsa_2047_x86.tar.bz2
    tar vjxf debian_ssh_rsa_4096_x86.tar.bz2
    tar vjxf debian_ssh_rsa_8192_1_4100_x86.tar.bz2
    cd -
  fi

  banner "tools - impacket smbserver.py"
  wget -Nq https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbserver.py

  banner "tools - drupalUserEnum.py"
  wget -Nq https://raw.githubusercontent.com/weaknetlabs/Penetration-Testing-Grimoire/master/Brute%20Force/Tools/drupalUserEnum.py

  banner "tools - https://github.com/pentestmonkey/smtp-user-enum"
  wget -Nq https://raw.githubusercontent.com/pentestmonkey/smtp-user-enum/master/smtp-user-enum.pl

  banner "tools - gpp-decrypt2.rb"
  wget -Nq https://raw.githubusercontent.com/weaknetlabs/Penetration-Testing-Grimoire/master/Tools/gpp-decrypt2.rb

  banner "tools - https://github.com/BC-SECURITY/Empire.git"
  git clone --depth=1 --recursive https://github.com/BC-SECURITY/Empire.git

  banner "tools - https://github.com/cobbr/Covenant.git"
  git clone --depth=1 --recursive https://github.com/cobbr/Covenant.git
cd -


if [ ! -d tools/NoSQLMap ]; then
  banner "tools - https://github.com/codingo/NoSQLMap.git"
  git clone --depth=1 --recursive https://github.com/codingo/NoSQLMap.git tools/NoSQLMap
  cd tools/NoSQLMap

    pip install couchdb
    pip install pbkdf2
    pip install ipcalc

  cd -
fi

