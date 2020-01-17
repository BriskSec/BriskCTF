mkdir -p tools_windows
cd tools_windows

  git clone --depth=1 --recursive https://github.com/bitsadmin/wesng.git
  git clone --depth=1 --recursive https://github.com/deepzec/Bad-Pdf.git

  if [ ! -d sysi ]; then
    wget https://download.sysinternals.com/files/SysinternalsSuite.zip
    unzip SysinternalsSuite.zip -d sysi
    rm SysinternalsSuite.zip
  fi

  if [ ! -d mimikatz ]; then
    wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200104/mimikatz_trunk.zip
    #TODO This fails sometimes due to API rate limiting
    #curl -s https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest \
    # | grep "zipball_url.*zip" \
    # | cut -d : -f 2,3 \
    # | tr -d \" \
    # | tr -d , \
    # | wget -qi -O mimikatz_trunk.zip -
    unzip mimikatz_trunk.zip -d mimikatz
    rm mimikatz_trunk.zip
  fi

cd -

git clone --depth=1 --recursive https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git tools_windows/Windows-Exploit-Suggester
cd tools_windows/Windows-Exploit-Suggester

  chmod +x windows-exploit-suggester.py
  ./windows-exploit-suggester.py --update

cd -