mkdir -p lists
cd lists

    git clone --depth=1 --recursive https://github.com/swisskyrepo/PayloadsAllTheThings.git
    git clone --depth=1 --recursive https://github.com/danielmiessler/SecLists.git
    git clone --depth=1 --recursive https://github.com/fuzzdb-project/fuzzdb.git
    git clone --depth=1 --recursive https://github.com/tennc/webshell.git

cd -
