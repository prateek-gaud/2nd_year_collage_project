#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cat > soc-monitor <<EOF
#!/usr/bin/env bash
cd "$DIR"
source .venv/bin/activate
exec sudo -E env PATH="\$PATH" SOC_INTERFACE="\${SOC_INTERFACE:-}" SOC_BPF="\${SOC_BPF:-ip or ip6 or arp}" python app.py
EOF
chmod +x soc-monitor
sudo cp soc-monitor /usr/local/bin/soc-monitor
echo "[+] Installed. Start with: sudo soc-monitor"
