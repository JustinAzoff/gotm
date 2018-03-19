Tools
=====

gotm-disk-cleanup
-----------------

This script will delete old PCAPs, once less than a certain threshold of free disk space remains.

```
usage: gotm-disk-cleanup [-h] -b BASEDIR -t THRESHOLD [-v]

Delete PCAPs from gotm when getting close to running out of disk

optional arguments:
  -h, --help    show this help message and exit
  -b BASEDIR    Base directory for PCAP storage (e.g. /srv for /srv/pcaps)
  -t THRESHOLD  Threshold (in GB) at which to start deleting PCAPs
  -v            Enable verbose output
```

It's suggested to run this hourly out of cron, e.g.:

```5 * * * * /usr/local/bin/gotm-disk-cleanup```
