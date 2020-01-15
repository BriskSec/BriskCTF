mkdir -p tools_windows
cd tools_windows

  git clone --depth=1 --recursive https://github.com/bitsadmin/wesng.git
  git clone --depth=1 --recursive https://github.com/deepzec/Bad-Pdf.git

  wget https://download.sysinternals.com/files/SysinternalsSuite.zip
  unzip SysinternalsSuite.zip -d sysi
  rm SysinternalsSuite.zip

  curl -s https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest \
   | grep "zipball_url.*zip" \
   | cut -d : -f 2,3 \
   | tr -d \" \
   | tr -d , \
   | wget -qi -O mimikatz_trunk.zip -
  unzip mimikatz_trunk.zip -d mimikatz
  rm mimikatz_trunk.zip

cd -
