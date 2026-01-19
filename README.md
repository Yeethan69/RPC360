# RPC360 - Discord rich presence for the 360

## Features

* Auto detect running game and update presence (OG Xbox games included).
* Pull info from Xbox Unity (name and icon).
* Customise console line presence, can make it anything.

## Usage

Put the RPC360.xex anywhere on your HDD or USB.
Edit config-example.json, rename to config.json and place it next to RPC360.xex.
Load plugin or set to autoload in dashlaunch.

Thats it.

It has not been too heavily tested so it may crash and some edge cases may break it.

## TODO

* \[ ] Make it more stable.
* \[ ] Add image fallbacks for games without icons.
* \[ ] Fix some edge cases.

## Credits

* [ClementDreptin - XexUtils](https://github.com/ClementDreptin/XexUtils) - the library used for networking and other tasks.
* [jsoncpp](https://github.com/open-source-parsers/jsoncpp) - the json library used.
