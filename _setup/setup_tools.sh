mkdir -p tools
cd tools

  git clone --depth=1 --recursive https://github.com/drwetter/testssl.sh.git
  git clone --depth=1 --recursive https://github.com/ayomawdb/AutoRecon.git
  git clone --depth=1 --recursive https://github.com/GDSSecurity/PadBuster.git
  git clone --depth=1 --recursive https://github.com/Va5c0/Steghide-Brute-Force-Tool.git
  git clone --depth=1 --recursive https://github.com/trinitronx/vncpasswd.py.git
  git clone --depth=1 --recursive https://github.com/jeroennijhof/vncpwd.git
  git clone --depth=1 --recursive https://github.com/trailofbits/protofuzz.git

  if [ ! -f vncpwd.exe ]; then
    wget http://aluigi.altervista.org/pwdrec/vncpwd.zip
    unzip vncpwd.zip -d tmp_vncpwd
    cp tmp_vncpwd/vncpwd.exe .
    rm -rf tmp_vncpwd
    rm vncpwd.zip
  fi

  if [ ! -d debian-ssh-master ]; then
    axel https://github.com/g0tmi1k/debian-ssh/archive/master.zip
    unzip debian-ssh-master.zip
    cd debian-ssh-master/common_keys
    tar vjxf debian_ssh_dsa_1024_x86.tar.bz2
    tar vjxf debian_ssh_rsa_2048_x86.tar.bz2
    cd -
    cd debian-ssh-master/uncommon_keys
    tar vjxf debian_ssh_rsa_1023_x86.tar.bz2
    tar vjxf debian_ssh_rsa_1024_x86.tar.bz2
    tar vjxf debian_ssh_rsa_2047_x86.tar.bz2
    tar vjxf debian_ssh_rsa_4096_x86.tar.bz2
    tar vjxf debian_ssh_rsa_8192_1_4100_x86.tar.bz2
    cd -
  fi

  wget -Nq https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbserver.py

cd -


if [ ! -d tools/NoSQLMap ]; then
  git clone --depth=1 --recursive https://github.com/codingo/NoSQLMap.git tools/NoSQLMap
  cd tools/NoSQLMap

    pip install couchdb
    pip install pbkdf2
    pip install ipcalc

  cd -
fi