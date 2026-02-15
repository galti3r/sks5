# sks5 System Installation

## Systemd

### Create user and directories

```bash
sudo useradd -r -s /usr/sbin/nologin sks5
sudo mkdir -p /etc/sks5 /var/lib/sks5 /var/log/sks5
sudo chown sks5:sks5 /var/lib/sks5 /var/log/sks5
```

### Install binary and config

```bash
sudo cp target/release/sks5 /usr/local/bin/sks5
sudo chmod 755 /usr/local/bin/sks5
sudo cp config.example.toml /etc/sks5/config.toml
sudo chown root:sks5 /etc/sks5/config.toml
sudo chmod 640 /etc/sks5/config.toml
```

### Install and enable service

```bash
sudo cp contrib/sks5.service /etc/systemd/system/sks5.service
sudo systemctl daemon-reload
sudo systemctl enable sks5
sudo systemctl start sks5
```

### Check status

```bash
sudo systemctl status sks5
sudo journalctl -u sks5 -f
```

### Reload configuration

```bash
sudo systemctl reload sks5
```
