Linux Mint:
1. install virtualbox and vagrant
2. in vagrantfile
2.1. change host port from 5000 to any free one (3000)
3. if your project folder is located in ntfs file system
insert  to vagrantfile
    config.ssh.insert_key = false
