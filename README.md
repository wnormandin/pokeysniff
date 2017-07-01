# pokeysniff.py
### a simple packet sniffer

This utility was designed as a bare-bones Python 3 packet sniffer for circumstances where other tools might not be available.
Usage follows these basic guidelines:
```
usage: pokeysniff.py [-h] [--filter [{tcp,udp,icmp} [{tcp,udp,icmp} ...]]]
                     [--src-port [SRC_PORT [SRC_PORT ...]]]
                     [--src-ip [SRC_IP [SRC_IP ...]]]
                     [--dest-port [DEST_PORT [DEST_PORT ...]]]
                     [--dest-ip [DEST_IP [DEST_IP ...]]] [--nocolor]
                     [--verbose] [--no-data]

optional arguments:
  -h, --help            show this help message and exit
  --filter [{tcp,udp,icmp} [{tcp,udp,icmp} ...]]
                        filter packets by type
  --src-port [SRC_PORT [SRC_PORT ...]]
                        filter packets by source port
  --src-ip [SRC_IP [SRC_IP ...]]
                        filter packets by source IP
  --dest-port [DEST_PORT [DEST_PORT ...]]
                        filter packets by destination port
  --dest-ip [DEST_IP [DEST_IP ...]]
                        filter packets by destination IP
  --nocolor             Skip colors in output
  --verbose             Enable verbose output
  --no-data             Skip printing raw data
```
The script can be obtained directly from my script repository
```
wget https://scripts.pokeybill.us/pokeysniff.py
```
Each filter allows for multiple arguments
```
python pokeysniff.py --dest-port 25 26 587 --dest-ip 8.8.4.4 129.33.214.82 --filter tcp udp
```
## To-Do:
* Implement ip-based filtering
* Improve port filtering
* Correct buffer delay
