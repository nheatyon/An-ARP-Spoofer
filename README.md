<h1 align="center">Welcome to An-ARP-Spoofer 👋</h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-1.0-blue.svg?cacheSeconds=2592000" />
  <a href="https://github.com/nheatyon/An-ARP-Spoofer/blob/main/LICENSE">
    <img alt="License: GNU--GPLv3" src="https://img.shields.io/badge/License-GNU--GPLv3-yellow.svg" />
  </a>
</p>

> A simple script written in Python 3.10 capable of performing an arp spoofing operation towards a given local ip address and interrupting its internet network flow, blocking access to it

## Install

To use the script via python, you need to download the source and go to the folder where the "requirements.txt" file is located.<br/>
Here you will need to execute the following command:
```sh
pip3 install -r requirements.txt
```
If you want to use the script on Windows, there will be an executable file in the repository releases (will need to be run as an administrator).

## Usage
Once the dependencies are installed, you will need to run the script and specify the various parameters.<br/>
* <b>gateway_ip</b> → <i>Default gateway IP</i><br/>
* <b>ip_address</b> → <i>IP address of the victim present on the network</i>
```sh
python arp_spoofer.py -g <gateway_ip> -i <ip_address>
```
As soon as the command is sent, the script starts running and will block the connection for that particular IP address as long as it is running.<br/>
To cancel everything and restore the connection, you will need to press <b>CTRL+C</b> and consequently exit the script

## Contributing

Any contribution to the project is really <b>appreciated</b>. Feel free to fork the project and commit your changes!<br/>
Use this script for educational purposes only! I do not take any responsibility for the use you will make of it
