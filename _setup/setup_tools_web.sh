mkdir -p tools_web
cd tools_web

    banner "tools - drupalUserEnum.py"
    wget -N https://raw.githubusercontent.com/weaknetlabs/Penetration-Testing-Grimoire/master/Brute%20Force/Tools/drupalUserEnum.py


cd -

if [ ! -d tools_web/NoSQLMap ]; then
  banner "tools - https://github.com/codingo/NoSQLMap.git"
  git clone --depth=1 --recursive https://github.com/codingo/NoSQLMap.git tools_web/NoSQLMap
  cd tools_web/NoSQLMap

    pip install couchdb
    pip install pbkdf2
    pip install ipcalc

  cd -
fi