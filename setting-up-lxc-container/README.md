# setting-up-lxc-container

Here is how I set up my Linux containers upon setup

```bash
apt update && apt upgrade -y
apt install -y sudo nmap tmux git vim
adduser jeremy
usermod -aG sudo jeremy
su jeremy
cd ~
mkdir -p ~/.ssh
```
