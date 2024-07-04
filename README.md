# NessusDiffWatcher
A tool for monitoring scan changes in Nessus and delivering them using the selected tool

# Installation

```bash
sudo apt install python3 python3-venv nessus
git clone https://github.com/NoCloud-today/NessusDiffWatcher.git
cd NessusDiffWatcher
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
chmod +x run.sh
vi settings.ini
sudo ./run.sh
```

An example crontab entry:
```crontab
*/5 * * * * sudo python3 /.../NessusDiffWatcher/run.sh
```

# Update to the latest version
```bash
git pull
```
