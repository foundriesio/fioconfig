Ignore this PR and Never merge it ! This is a simple daemon designed to manage configurartion data for an
embedded device. Its based on a customized OTA Community Edition
device-gateway endpoint, but the idea used could be generic to any
system wanting to employ secure configuration management.

## How It Works

OTA devices communicate with a device-gateway using SSL client
authentication. This means the public key of each device is known. By
default, devices will have Ellipitcal Curve keys. Using a technique
known as [ECIES](https://cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme)
a the configuration values can be encrypted client-side and sent to
the device-gateway so that it has no knowledge of a device's configuration
values. The device can then pull down the encrypted configuration and
use its private key to decrypt.

The encrypted file is stored to a persistent location on disk. At boot,
a fioconfig can extract this data to tmpfs (/var/run/secrets) so that
they are only available at runtime.


## How to build
`make bin/fioconfig-linux-amd64`
`make test`
