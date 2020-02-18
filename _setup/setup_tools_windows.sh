mkdir -p tools_windows
cd tools_windows

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
    wget -N -O mimikatz_trunk.zip mimi https://github.com`curl https://github.com/gentilkiwi/mimikatz/releases | grep "archive" | grep "zip" | head -1 | cut -d "\"" -f2`
    #Following call fails sometimes due to API rate limiting. Hence reading HTML. 
    #curl -s https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest \
    # | grep "zipball_url.*zip" \
    # | cut -d : -f 2,3 \
    # | tr -d \" \
    # | tr -d , \
    # | wget -qi -O mimikatz_trunk.zip -
    unzip mimikatz_trunk.zip
    rm mimikatz_trunk.zip
    mv mimikatz-* mimikatz
  fi

cd -

banner "tools_windows - https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git"
git clone --depth=1 --recursive https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git tools_windows/Windows-Exploit-Suggester
cd tools_windows/Windows-Exploit-Suggester

  banner "tools_windows - Updating https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git"
  chmod +x windows-exploit-suggester.py
  ./windows-exploit-suggester.py --update

cd -
