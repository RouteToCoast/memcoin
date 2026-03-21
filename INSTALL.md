# Installing Memcoin

## System Requirements

- 64-bit operating system
- 16 GB RAM minimum (7 GB per mining thread + system overhead)
- 10 GB free disk space

---

## Ubuntu 22.04 LTS

### 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build libboost-all-dev \
    libssl-dev libdb-dev libdb++-dev libevent-dev libminiupnpc-dev \
    libzmq3-dev libgmp-dev git python3 libnatpmp-dev pkg-config
```

### 2. Clone and Build

```bash
git clone https://github.com/RouteToCoast/memcoin.git
cd memcoin
mkdir build && cd build
cmake -GNinja .. \
    -DBUILD_BITCOIN_QT=OFF \
    -DBUILD_BITCOIN_SEEDER=OFF
ninja -j$(nproc)
```

### 3. Configure

```bash
mkdir -p ~/.memcoin
cat > ~/.memcoin/memcoin.conf << 'EOF'
rpcuser=memcoin
rpcpassword=your_password_here
rpcallowip=127.0.0.1
server=1
listen=1
EOF
```

### 4. Run

```bash
# Start node
./src/memcoind -daemon

# Check status
./src/memcoin-cli getblockchaininfo

# Stop node
./src/memcoin-cli stop
```

---

## Ubuntu 24.04 LTS and later

Ubuntu 24.04 and later do not include BerkeleyDB in the default package
repository. BerkeleyDB must be installed separately before building Memcoin.
Ubuntu 22.04 LTS is recommended.

---

## Windows (via WSL)

WSL (Windows Subsystem for Linux) runs Ubuntu natively inside Windows
without a virtual machine.

### Step 1 — Install WSL with Ubuntu 22.04 LTS

Open **PowerShell as Administrator** and run:

```powershell
wsl --install -d Ubuntu-22.04
```

Restart your computer when prompted.

### Step 2 — Set Up Ubuntu

After restarting, Ubuntu will launch and ask you to create a username and
password. Enter any username and password you like.

### Step 3 — Install Memcoin

Inside the Ubuntu terminal, follow the **Ubuntu 22.04 LTS** instructions
above from Step 1 onward.

### Notes

- The Ubuntu terminal can be reopened anytime by searching **Ubuntu 22.04**
  in the Start menu, or running `wsl` in PowerShell
- WSL requires Windows 10 version 2004 or later, or Windows 11
- Your Windows files are accessible inside WSL at `/mnt/c/`
