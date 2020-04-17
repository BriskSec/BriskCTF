mkdir -p tools/web
cd tools/web

    wget -O log-server.py -N https://gist.githubusercontent.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7/raw/a6a1d090ac8549dac8f2bd607bd64925de997d40/server.py

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
    git clone --depth=1 --recursive https://github.com/P0cL4bs/Kadimus.git
    cd Kadimus
    sudo apt install --no-upgrade libcurl4-openssl-dev libpcre3-dev libssh-dev make
    ./configure
    cd ..

    wget -N https://raw.githubusercontent.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration/master/nosqli-user-pass-enum.py

    git clone --depth=1 --recursive https://github.com/Valve/fingerprintjs2.git
    cd fingerprintjs2
cat <<\EOT >fingerprintjs2.html
<!doctype html>
<html>
<head>
<title>Blank Page</title> </head>
<body>
<h1>You have been given the finger!</h1> <script src="fingerprint2.js"></script> <script>
var d1 = new Date();
var options = {};
Fingerprint2.get(options, function (components) {
var values = components.map(function (component) { return component.value }) var murmur = Fingerprint2.x64hash128(values.join(''), 31)
var clientfp = "Client browser fingerprint: " + murmur + "\n\n";
var d2 = new Date();
var timeString = "Time to calculate fingerprint: " + (d2 - d1) + "ms\n\n";
var details = "Detailed information: \n"; if(typeof window.console !== "undefined") {
for (var index in components) { var obj = components[index]; var value = obj.value;
if (value !== null) {
var line = obj.key + " = " + value.toString().substr(0, 150); details += line + "\n";
}
} }
var xmlhttp = new XMLHttpRequest();
xmlhttp.open("POST", "/fp/js.php"); xmlhttp.setRequestHeader("Content-Type", "application/txt"); xmlhttp.send(clientfp + timeString + details);
      });
  </script>
</body>
</html>
EOT

cd ../..