# COMP8005 Assignment 2

## Custom Monitoring Toolkit

This project is a custom monitoring toolkit designed to monitor various aspects of a process running on a Linux system. It provides functionalities to monitor process statistics, network traffic, active network connections, and active ports used by the process.

### Table of Contents

- [Installation](#installation)
- [Usage](#usage)
    -[Options](#options)
- [Modules](#modules)
  - [ProcessStats](#processstats)
  - [NetworkTrafficMonitor](#networktrafficmonitor)
  - [ConnectionsMonitor](#connectionsmonitor)
  - [ActivePortsMonitor](#activeportsmonitor)
- [Utilities](#utilities)
- [Contributing](#contributing)
- [License](#license)

### Installation

1. Clone the repository:

    ```zsh
    git clone https://github.com/AgamMS10/COMP8005_A2.git
    cd monitoring-toolkit
    ```

2. Ensure you have Python 3.6+ installed.

3. Install the required dependencies:

    ```zsh
    pip install -r requirements.txt
    ```

### Usage

To run the monitoring toolkit, use the following command:

```zsh
python NetworkMonitor.py <pid> [options]
```

#### Options

- `pid` : The PID of the process to monitor.
- `-i, --interval`: Update interval in seconds (default: 5).
- `--network-traffic`: Monitor network traffic (bytes sent/received).
- `--connections`: Monitor active network connections.
- `--active-ports`: Monitor active ports used by the process.

#### Example

```zsh
python NetworkMonitor.py 1234 -i 1 --network-traffic --connections --active-ports
```

### Modules

#### ProcessStats

The `ProcessStats` class provides methods to retrieve and display information about a process.

- **File**: `modules/process_stats.py`
- **Class**: `ProcessStats`

#### NetworkTrafficMonitor

The `NetworkTrafficMonitor` class monitors the network traffic (bytes sent/received) for a process.

- **File**: `modules/network_traffic.py`
- **Class**: `NetworkTrafficMonitor`

#### ConnectionsMonitor

The `ConnectionsMonitor` class monitors the active network connections for a process.

- **File**: `modules/connections.py`
- **Class**: `ConnectionsMonitor`

#### ActivePortsMonitor

The `ActivePortsMonitor` class monitors the active ports used by a process.

- **File**: `modules/active_ports.py`
- **Class**: `ActivePortsMonitor`

### Utilities

The `utils` module provides utility functions used across different modules.

- **File**: `modules/utils.py`
- **Function**: `tcp_state`

### Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

### License

Uhh License ?.
