mkdir -p tools/linux
cd tools/linux

    if [ ! -f debian-ssh-master.zip ]; then
        banner "tools - https://github.com/g0tmi1k/debian-ssh"
        axel https://github.com/g0tmi1k/debian-ssh/archive/master.zip
        unzip debian-ssh-master.zip
        cd debian-ssh-master/common_keys
        banner "tools - extracting common_keys - https://github.com/g0tmi1k/debian-ssh"
        tar vjxf debian_ssh_dsa_1024_x86.tar.bz2
        tar vjxf debian_ssh_rsa_2048_x86.tar.bz2
        cd ../..
        cd debian-ssh-master/uncommon_keys
        banner "tools - extracting uncommon_keys - https://github.com/g0tmi1k/debian-ssh"
        tar vjxf debian_ssh_rsa_1023_x86.tar.bz2
        tar vjxf debian_ssh_rsa_1024_x86.tar.bz2
        tar vjxf debian_ssh_rsa_2047_x86.tar.bz2
        tar vjxf debian_ssh_rsa_4096_x86.tar.bz2
        tar vjxf debian_ssh_rsa_8192_1_4100_x86.tar.bz2
        cd ../..
        #rm debian-ssh-master.zip
    fi
    
cd ../..