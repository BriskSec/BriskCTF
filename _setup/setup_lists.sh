mkdir -p public/lists
cd public/lists

    banner "lists : https://github.com/swisskyrepo/PayloadsAllTheThings"
    git clone --depth=1 --recursive https://github.com/swisskyrepo/PayloadsAllTheThings.git

    banner "lists : https://github.com/danielmiessler/SecLists"
    git clone --depth=1 --recursive https://github.com/danielmiessler/SecLists.git

    banner "lists : https://github.com/fuzzdb-project/fuzzdb"
    git clone --depth=1 --recursive https://github.com/fuzzdb-project/fuzzdb.git

    banner "lists : https://github.com/tennc/webshell"
    git clone --depth=1 --recursive https://github.com/tennc/webshell.git

    banner "lists : https://github.com/andrew-d/static-binaries"
    git clone --depth=1 --recursive https://github.com/andrew-d/static-binaries.git

    banner "lists - https://github.com/andrew-d/static-binaries.git"
    git clone --depth=1 --recursive https://github.com/andrew-d/static-binaries.git

    banner "lists - https://github.com/nice-registry/all-the-package-names.git"
    git clone --depth=1 --recursive https://github.com/nice-registry/all-the-package-names.git

    banner "lists - https://github.com/nice-registry/all-the-package-repos.git"
    git clone --depth=1 --recursive https://github.com/nice-registry/all-the-package-repos.git
cd ../..
