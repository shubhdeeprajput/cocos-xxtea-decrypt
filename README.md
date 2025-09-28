# cocos-xxtea-decrypt
A command line utility to decrypt .jsc files of cocos android applications. 

## Usage
First clone the repo and make sure the script has execution permission.
```
git clone shubhdeeprajput/cocos-xxtea-decrypt
cd cocos-xxtea-decrypt
chmod +x cocos-decrypt.sh
```
Provide the path to the apk or bundle zip file, address of the xxtea_decrypt function from libcocos.so and output path where decrypted files will be saved(default is current directory).
Example:
```
./cocos-decrypt.sh <path/to/apk.apk or path/to/bundle.zip> <decrypt function address> <output path>
```

## Requirements
The script requires `adb`, `android sdk` present on the system, attached device up and running, `frida` on system and `frida-server` running on device (**Note:** The version of the frida-server running on device should be exact same as used by python script, see `requirements.txt`, else python frida hook will fail.
