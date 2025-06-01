# Loginer
Very cool app

## Setup

Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install Tauri CLI
```bash
npm install --save-dev @tauri-apps/cli@latest
```

Install sql-cipher
```bash
sudo apt-get install sqlcipher libsqlcipher-dev
```

Install build-tools
```bash
sudo apt-get install build-essential libssl-dev pkg-config
```

Unzip the source archive
```bash
unzip loginer.zip -d loginer
cd ./loginer
```

Install deps
```bash
yarn install
```

Build it
```bash
yarn tauri build
```

Or run it in dev
```bash
yarn tauri dev
```

Keep in mind, cause there is sqlcipher you'll need to build opnessl-sys. That takes some time.. 