# P4_16 Implementation
## Getting started

You can exeucte the following steps to deploy **MORP4** on a sample network of 3 switches (with 1 host connected to each):
- Start the network:
```bash
cd p4src
sudo p4run
```
- Start the controller (in a different terminal)
```bash
cd p4src/controller
sudo python3 app.py
```
- Start the CLI (in a different terminal)
```bash
cd p4src/controller
sudo python3 cli.py
```