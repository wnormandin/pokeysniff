# pokeysniff.py
### a simple packet sniffer

This utility was designed as a bare-bones Python 3 packet sniffer for circumstances where other tools might not be available.
Usage follows these basic guidelines:

```
usage: pokeysniff.py [-h] [--filter [{tcp,udp,icmp}]] [--src_port SRC_PORT]
          [--dest_port DEST_PORT] [--nocolor]

optional arguments:
  -h, --help            show this help message and exit
  --filter [{tcp,udp,icmp}]
                        filter packets by type
  --src_port SRC_PORT   specify a source port to monitor
  --dest_port DEST_PORT
                        specify a destination port to monitor
  --nocolor             Skip colors in output
```

The script can be obtained directly from my script repository

```
# python3 <(curl -s https://scripts.pokeybill.us/pokeysniff.py) --help
usage: 63 [-h] [--filter [{tcp,udp,icmp}]] [--src_port SRC_PORT]
          [--dest_port DEST_PORT] [--nocolor]

optional arguments:
  -h, --help            show this help message and exit
  --filter [{tcp,udp,icmp}]
                        filter packets by type
  --src_port SRC_PORT   specify a source port to monitor
  --dest_port DEST_PORT
                        specify a destination port to monitor
  --nocolor             Skip colors in output
```

## To-Do:
* Implement ip-based filtering
* Improve port filtering
* Correct buffer delay
