# Tofino Implementation
## Getting started


After deploying **MORP4** in the Tofino model/ASIC:
- Start the controller which:
    - initializes the switch
    - periodically checks for the state of a prefix
    - waits for incoming HTTP requests
    ```bash
    cd p4src-tofino/controller
    python3 app.py [--interval 3] [--global-table-size 4194304] [--dark-table-size 1024] [--alpha 1] [--outgoing 1] [--incoming 2] [--monitored ../input_files/monitored.txt]
    ```
- Start the CLI:
    ```bash
    cd p4src-tofino/controller
    python3 cli.py
    ```
