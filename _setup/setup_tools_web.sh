mkdir -p tools/web
cd tools/web

    banner "tools - drupalUserEnum.py"
    wget -N https://raw.githubusercontent.com/weaknetlabs/Penetration-Testing-Grimoire/master/Brute%20Force/Tools/drupalUserEnum.py

    if ! $useRecommended; then
        # Not recommended since this requires python3-dev (will need to update libs)
        if [ ! -d weevely3 ]; then
            banner "tools - weevely3 - Weaponized web shell - PHP - https://github.com/epinna/weevely3.git"
            sudo apt-get install --no-upgrade python3-dev

            git clone --depth=1 --recursive https://github.com/epinna/weevely3.git
            cd weevely3
            virtualenv venv -p python3
            source venv/bin/activate
            pip install -r requirements.txt
            python3 weevely.py
            deactivate
            cd ..
        fi
    fi


    if [ ! -d NoSQLMap ]; then
        banner "tools - https://github.com/codingo/NoSQLMap.git"
        git clone --depth=1 --recursive https://github.com/codingo/NoSQLMap.git
        cd NoSQLMap
        virtualenv venv -p python2
        source venv/bin/activate
        pip install couchdb
        pip install pbkdf2
        pip install ipcalc
        pip install six
        pip install pymongo
        pip install requests
        python2 nosqlmap.py --help
        deactivate
        cd ..
    fi

    banner "tools - davtest 1.2 - improved - https://github.com/cldrn/davtest.git"
    git clone --depth=1 --recursive https://github.com/cldrn/davtest.git

    banner "tools - https://github.com/nccgroup/shocker.git"
    git clone --depth=1 --recursive https://github.com/nccgroup/shocker.git

    banner "tools - fimap - sqlmap for lfi rfi in PHP - https://github.com/kurobeats/fimap.git"
    # https://kaoticcreations.blogspot.com/2011/08/automated-lfirfi-scanning-exploiting.html
    git clone --depth=1 --recursive https://github.com/kurobeats/fimap.git

    banner "tools - cms-explorer - https://github.com/FlorianHeigl/cms-explorer.git"
    git clone --depth=1 --recursive https://github.com/FlorianHeigl/cms-explorer.git

    banner "tools - Kadimus - LFI - https://github.com/P0cL4bs/Kadimus.git"
    git clone https://github.com/P0cL4bs/Kadimus.git
    cd Kadimus
    sudo apt install --no-upgrade libcurl4-openssl-dev libpcre3-dev libssh-dev make
    ./configure
    cd ..

cd ..