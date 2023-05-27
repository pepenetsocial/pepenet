# pepenet
Copyright (c) 2023 pepenet. 
Copyright (c) 2014-2022 The Monero Project.  
Portions Copyright (c) 2012-2013 The Cryptonote developers.

## Table of Contents

  - [Development resources](#development-resources)
  - [Vulnerability response](#vulnerability-response)
  - [Research](#research)
  - [Announcements](#announcements)
  - [Translations](#translations)
  - [Coverage](#coverage)
  - [Introduction](#introduction)
  - [About this project](#about-this-project)
  - [Supporting the project](#supporting-the-project)
  - [License](#license)
  - [Contributing](#contributing)
  - [Scheduled software upgrades](#scheduled-software-upgrades)
  - [Release staging schedule and protocol](#release-staging-schedule-and-protocol)
  - [Compiling pepenet from source](#compiling-pepenet-from-source)
    - [Dependencies](#dependencies)
  - [Internationalization](#Internationalization)
  - [Using Tor](#using-tor)
  - [Pruning](#Pruning)
  - [Debugging](#Debugging)
  - [Known issues](#known-issues)

## Development resources
Google and source code.

## Vulnerability response

Call the cops ;D

## Research

Intense research process - copy paste monero's research.

## Announcements


## Translations
The CLI wallet is available in different languages.

## Coverage

## Introduction

Pepenet is a decentralised and blockchain based social network. It is resistant to censorship, regulation, raids, laws and most importantly politics.
As long as there are enough tech-savy people that support full freedom of speech it will not be stopped.

Pepenet was inpired by the unjust shaming of the pepe meme. Now it's almost on the same level as swastika because of some unreasonable people. This fact suggest that our society has a serious problem with freedom of expression if a cartoon frog is recognized as a hate symbol by a real organization (https://www.adl.org/resources/hate-symbol/pepe-frog).

The vast majority of pepenet (~100%) is based on the monero project (https://github.com/monero-project/monero). The only real modification is the use of transaction fields as placeholders for PEP-ing (short status updates similar to tweets) and posting (post with title and body limited to 1024 bytes of LZMA compressed text)

Users will have to pay transaction fees for their posting priviliges with the pepenet currency. Longer posts <-> higher transaction fees.

Users can remain completely anonymous or choose a ECDSA identity and a variable pseudonym. The ECDSA identity will be used for authenticity and verification. This will allow users to follow the content creators that they are interested in.

This project would not be possible without monero. Out of respect the original description is included here:

Monero is a private, secure, untraceable, decentralised digital currency. You are your bank, you control your funds, and nobody can trace your transfers unless you allow them to do so.

**Privacy:** Monero uses a cryptographically sound system to allow you to send and receive funds without your transactions being easily revealed on the blockchain (the ledger of transactions that everyone has). This ensures that your purchases, receipts, and all transfers remain private by default.

**Security:** Using the power of a distributed peer-to-peer consensus network, every transaction on the network is cryptographically secured. Individual wallets have a 25-word mnemonic seed that is only displayed once and can be written down to backup the wallet. Wallet files should be encrypted with a strong passphrase to ensure they are useless if ever stolen.

**Untraceability:** By taking advantage of ring signatures, a special property of a certain type of cryptography, Monero is able to ensure that transactions are not only untraceable but have an optional measure of ambiguity that ensures that transactions cannot easily be tied back to an individual user or computer.

**Decentralization:** The utility of Monero depends on its decentralised peer-to-peer consensus network - anyone should be able to run the pepenet software, validate the integrity of the blockchain, and participate in all aspects of the pepenet network using consumer-grade commodity hardware. Decentralization of the pepenet network is maintained by software development that minimizes the costs of running the pepenet software and inhibits the proliferation of specialized, non-commodity hardware.

## About this project

This is the core implementation of pepenet. It is open source and completely free to use without restrictions, except for those specified in the license agreement below. There are no restrictions on anyone creating an alternative implementation of Monero that uses the protocol and network in a compatible manner.

As with many development projects, the repository on GitHub is considered to be the "staging" area for the latest changes. Before changes are merged into that branch on the main repository, they are tested by individual developers in their own branches, submitted as a pull request, and then subsequently tested by contributors who focus on testing and code reviews. That having been said, the repository should be carefully considered before using it in a production environment, unless there is a patch in the repository for a particular show-stopping issue you are experiencing. It is generally a better idea to use a tagged release for stability.

**Anyone is welcome to contribute to the pepenet codebase!** If you have a fix or code change, feel free to submit it as a pull request directly to the "master" branch. In cases where the change is relatively small or does not affect other parts of the codebase, it may be merged in immediately by any one of the collaborators. On the other hand, if the change is particularly large or complex, it is expected that it will be discussed at length either well in advance of the pull request being submitted, or even directly on the pull request.

## Supporting the project
Just run a full node :D

## License

See [LICENSE](LICENSE).

## Contributing

If you want to help out, see [CONTRIBUTING](docs/CONTRIBUTING.md) for a set of guidelines.

## Scheduled software upgrades

## Release staging schedule and protocol

## Compiling pepenet from source

### Dependencies

The following table summarizes the tools and libraries required to build. A
few of the libraries are also included in this repository (marked as
"Vendored"). By default, the build uses the library installed on the system
and ignores the vendored sources. However, if no library is found installed on
the system, then the vendored source will be built and used. The vendored
sources are also used for statically-linked builds because distribution
packages often include only shared library binaries (`.so`) but not static
library archives (`.a`).

| Dep          | Min. version  | Vendored | Debian/Ubuntu pkg    | Arch pkg     | Void pkg           | Fedora pkg          | Optional | Purpose         |
| ------------ | ------------- | -------- | -------------------- | ------------ | ------------------ | ------------------- | -------- | --------------- |
| GCC          | 5             | NO       | `build-essential`    | `base-devel` | `base-devel`       | `gcc`               | NO       |                 |
| CMake        | 3.5           | NO       | `cmake`              | `cmake`      | `cmake`            | `cmake`             | NO       |                 |
| pkg-config   | any           | NO       | `pkg-config`         | `base-devel` | `base-devel`       | `pkgconf`           | NO       |                 |
| Boost        | 1.58          | NO       | `libboost-all-dev`   | `boost`      | `boost-devel`      | `boost-devel`       | NO       | C++ libraries   |
| OpenSSL      | basically any | NO       | `libssl-dev`         | `openssl`    | `libressl-devel`   | `openssl-devel`     | NO       | sha256 sum      |
| libzmq       | 4.2.0         | NO       | `libzmq3-dev`        | `zeromq`     | `zeromq-devel`     | `zeromq-devel`      | NO       | ZeroMQ library  |
| OpenPGM      | ?             | NO       | `libpgm-dev`         | `libpgm`     |                    | `openpgm-devel`     | NO       | For ZeroMQ      |
| libnorm[2]   | ?             | NO       | `libnorm-dev`        |              |                    |                     | YES      | For ZeroMQ      |
| libunbound   | 1.4.16        | YES      | `libunbound-dev`     | `unbound`    | `unbound-devel`    | `unbound-devel`     | NO       | DNS resolver    |
| libsodium    | ?             | NO       | `libsodium-dev`      | `libsodium`  | `libsodium-devel`  | `libsodium-devel`   | NO       | cryptography    |
| libunwind    | any           | NO       | `libunwind8-dev`     | `libunwind`  | `libunwind-devel`  | `libunwind-devel`   | YES      | Stack traces    |
| liblzma      | any           | NO       | `liblzma-dev`        | `xz`         | `liblzma-devel`    | `xz-devel`          | YES      | For libunwind   |
| libreadline  | 6.3.0         | NO       | `libreadline6-dev`   | `readline`   | `readline-devel`   | `readline-devel`    | YES      | Input editing   |
| expat        | 1.1           | NO       | `libexpat1-dev`      | `expat`      | `expat-devel`      | `expat-devel`       | YES      | XML parsing     |
| GTest        | 1.5           | YES      | `libgtest-dev`[1]    | `gtest`      | `gtest-devel`      | `gtest-devel`       | YES      | Test suite      |
| ccache       | any           | NO       | `ccache`             | `ccache`     | `ccache`           | `ccache`            | YES      | Compil. cache   |
| Doxygen      | any           | NO       | `doxygen`            | `doxygen`    | `doxygen`          | `doxygen`           | YES      | Documentation   |
| Graphviz     | any           | NO       | `graphviz`           | `graphviz`   | `graphviz`         | `graphviz`          | YES      | Documentation   |
| lrelease     | ?             | NO       | `qttools5-dev-tools` | `qt5-tools`  | `qt5-tools`        | `qt5-linguist`      | YES      | Translations    |
| libhidapi    | ?             | NO       | `libhidapi-dev`      | `hidapi`     | `hidapi-devel`     | `hidapi-devel`      | YES      | Hardware wallet |
| libusb       | ?             | NO       | `libusb-1.0-0-dev`   | `libusb`     | `libusb-devel`     | `libusbx-devel`     | YES      | Hardware wallet |
| libprotobuf  | ?             | NO       | `libprotobuf-dev`    | `protobuf`   | `protobuf-devel`   | `protobuf-devel`    | YES      | Hardware wallet |
| protoc       | ?             | NO       | `protobuf-compiler`  | `protobuf`   | `protobuf`         | `protobuf-compiler` | YES      | Hardware wallet |
| libudev      | ?             | NO       | `libudev-dev`        | `systemd`    | `eudev-libudev-devel` | `systemd-devel`  | YES      | Hardware wallet |

[1] On Debian/Ubuntu `libgtest-dev` only includes sources and headers. You must
build the library binary manually. This can be done with the following command `sudo apt-get install libgtest-dev && cd /usr/src/gtest && sudo cmake . && sudo make`
then:

* on Debian:
  `sudo mv libg* /usr/lib/`
* on Ubuntu:
  `sudo mv lib/libg* /usr/lib/`

[2] libnorm-dev is needed if your zmq library was built with libnorm, and not needed otherwise

Install all dependencies at once on Debian/Ubuntu:

```
sudo apt update && sudo apt install build-essential cmake pkg-config libssl-dev libzmq3-dev libunbound-dev libsodium-dev libunwind8-dev liblzma-dev libreadline6-dev libexpat1-dev libpgm-dev qttools5-dev-tools libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler libudev-dev libboost-chrono-dev libboost-date-time-dev libboost-filesystem-dev libboost-locale-dev libboost-program-options-dev libboost-regex-dev libboost-serialization-dev libboost-system-dev libboost-thread-dev python3 ccache doxygen graphviz
```

Install all dependencies at once on Arch:
```
sudo pacman -Syu --needed base-devel cmake boost openssl zeromq libpgm unbound libsodium libunwind xz readline expat gtest python3 ccache doxygen graphviz qt5-tools hidapi libusb protobuf systemd
```

Install all dependencies at once on Fedora:
```
sudo dnf install gcc gcc-c++ cmake pkgconf boost-devel openssl-devel zeromq-devel openpgm-devel unbound-devel libsodium-devel libunwind-devel xz-devel readline-devel expat-devel gtest-devel ccache doxygen graphviz qt5-linguist hidapi-devel libusbx-devel protobuf-devel protobuf-compiler systemd-devel
```

Install all dependencies at once on openSUSE:

```
sudo zypper ref && sudo zypper in cppzmq-devel libboost_chrono-devel libboost_date_time-devel libboost_filesystem-devel libboost_locale-devel libboost_program_options-devel libboost_regex-devel libboost_serialization-devel libboost_system-devel libboost_thread-devel libexpat-devel libminiupnpc-devel libsodium-devel libunwind-devel unbound-devel cmake doxygen ccache fdupes gcc-c++ libevent-devel libopenssl-devel pkgconf-pkg-config readline-devel xz-devel libqt5-qttools-devel patterns-devel-C-C++-devel_C_C++
```

Install all dependencies at once on macOS with the provided Brewfile:

```
brew update && brew bundle --file=contrib/brew/Brewfile
```

FreeBSD 12.1 one-liner required to build dependencies:

```
pkg install git gmake cmake pkgconf boost-libs libzmq4 libsodium unbound
```

### Cloning the repository

Clone recursively to pull-in needed submodule(s):

```
git clone --recursive https://github.com/azx19/pepenet
```

If you already have a repo cloned, initialize and update:

```
cd pepenet && git submodule init && git submodule update
```

*Note*: If there are submodule differences between branches, you may need 
to use `git submodule sync && git submodule update` after changing branches
to build successfully.

### Build instructions

Pepenet uses the CMake build system and a top-level [Makefile](Makefile) that
invokes cmake commands as needed.

#### On Linux and macOS

* Install the dependencies
* Change to the root of the source code directory, change to the most recent release branch, and build:

    ```bash
    cd pepenet
    git checkout release-v0.18
    make
    ```

    *Optional*: If your machine has several cores and enough memory, enable
    parallel build by running `make -j<number of threads>` instead of `make`. For
    this to be worthwhile, the machine should have one core and about 2GB of RAM
    available per thread.

    *Note*: The instructions above will compile the most stable release of the
    pepenet software. If you would like to use and test the most recent software,
    use `git checkout master`. The master branch may contain updates that are
    both unstable and incompatible with release software, though testing is always
    encouraged.

* The resulting executables can be found in `build/release/bin`

* Add `PATH="$PATH:$HOME/pepenet/build/release/bin"` to `.profile`

* Run pepenet with `pepenetd --detach`

* **Optional**: build and run the test suite to verify the binaries:

    ```bash
    make release-test
    ```

    *NOTE*: `core_tests` test may take a few hours to complete.

* **Optional**: to build binaries suitable for debugging:

    ```bash
    make debug
    ```

* **Optional**: to build statically-linked binaries:

    ```bash
    make release-static
    ```

Dependencies need to be built with -fPIC. Static libraries usually aren't, so you may have to build them yourself with -fPIC. Refer to their documentation for how to build them.

* **Optional**: build documentation in `doc/html` (omit `HAVE_DOT=YES` if `graphviz` is not installed):

    ```bash
    HAVE_DOT=YES doxygen Doxyfile
    ```

* **Optional**: use ccache not to rebuild translation units, that haven't really changed. Pepenet's CMakeLists.txt file automatically handles it

    ```bash
    sudo apt install ccache
    ```

#### On the Raspberry Pi

Tested on a Raspberry Pi Zero with a clean install of minimal Raspbian Stretch (2017-09-07 or later) from https://www.raspberrypi.org/downloads/raspbian/. If you are using Raspian Jessie, [please see note in the following section](#note-for-raspbian-jessie-users).

* `apt-get update && apt-get upgrade` to install all of the latest software

* Install the dependencies for pepenet from the 'Debian' column in the table above.

* Increase the system swap size:

    ```bash
    sudo /etc/init.d/dphys-swapfile stop  
    sudo nano /etc/dphys-swapfile  
    CONF_SWAPSIZE=2048
    sudo /etc/init.d/dphys-swapfile start
    ```

* If using an external hard disk without an external power supply, ensure it gets enough power to avoid hardware issues when syncing, by adding the line "max_usb_current=1" to /boot/config.txt

* Clone pepenet and checkout the most recent release version:

    ```bash
    git clone git@github.com:azx19/pepenet.git
    cd pepenet
    git checkout "branch of latest version here"
    ```

* Build:

    ```bash
    USE_SINGLE_BUILDDIR=1 make release
    ```

* Wait 4-6 hours

* The resulting executables can be found in `build/release/bin`

* Add `export PATH="$PATH:$HOME/pepenet/build/release/bin"` to `$HOME/.profile`

* Run `source $HOME/.profile`

* Run pepenet with `pepenetd --detach`

* You may wish to reduce the size of the swap file after the build has finished, and delete the boost directory from your home directory

#### *Note for Raspbian Jessie users:*

If you are using the older Raspbian Jessie image, compiling pepenet is a bit more complicated. The version of Boost available in the Debian Jessie repositories is too old to use with pepenet, and thus you must compile a newer version yourself. The following explains the extra steps and has been tested on a Raspberry Pi 2 with a clean install of minimal Raspbian Jessie.

* As before, `apt-get update && apt-get upgrade` to install all of the latest software, and increase the system swap size

    ```bash
    sudo /etc/init.d/dphys-swapfile stop
    sudo nano /etc/dphys-swapfile
    CONF_SWAPSIZE=2048
    sudo /etc/init.d/dphys-swapfile start
    ```


* Then, install the dependencies for pepenet except for `libunwind` and `libboost-all-dev`

* Install the latest version of boost (this may first require invoking `apt-get remove --purge libboost*-dev` to remove a previous version if you're not using a clean install):

    ```bash
    cd
    wget https://sourceforge.net/projects/boost/files/boost/1.72.0/boost_1_72_0.tar.bz2
    tar xvfo boost_1_72_0.tar.bz2
    cd boost_1_72_0
    ./bootstrap.sh
    sudo ./b2
    ```

* Wait ~8 hours

    ```bash    
    sudo ./bjam cxxflags=-fPIC cflags=-fPIC -a install
    ```

* Wait ~4 hours

* From here, follow the [general Raspberry Pi instructions](#on-the-raspberry-pi) from the "Clone pepenet and checkout most recent release version" step.

#### On Windows:

Binaries for Windows are built on Windows using the MinGW toolchain within
[MSYS2 environment](https://www.msys2.org). The MSYS2 environment emulates a
POSIX system. The toolchain runs within the environment and *cross-compiles*
binaries that can run outside of the environment as a regular Windows
application.

**Preparing the build environment**

* Download and install the [MSYS2 installer](https://www.msys2.org), either the 64-bit or the 32-bit package, depending on your system.
* Open the MSYS shell via the `MSYS2 Shell` shortcut
* Update packages using pacman:

    ```bash
    pacman -Syu
    ```

* Exit the MSYS shell using Alt+F4
* Edit the properties for the `MSYS2 Shell` shortcut changing "msys2_shell.bat" to "msys2_shell.cmd -mingw64" for 64-bit builds or "msys2_shell.cmd -mingw32" for 32-bit builds
* Restart MSYS shell via modified shortcut and update packages again using pacman:

    ```bash
    pacman -Syu
    ```


* Install dependencies:

    To build for 64-bit Windows:

    ```bash
    pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-unbound
    ```

    To build for 32-bit Windows:

    ```bash
    pacman -S mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium mingw-w64-i686-hidapi mingw-w64-i686-unbound
    ```

* Open the MingW shell via `MinGW-w64-Win64 Shell` shortcut on 64-bit Windows
  or `MinGW-w64-Win64 Shell` shortcut on 32-bit Windows. Note that if you are
  running 64-bit Windows, you will have both 64-bit and 32-bit MinGW shells.

**Cloning**

* To git clone, run:

    ```bash
    git clone --recursive https://github.com/pepenet-project/pepenet.git
    ```

**Building**

* Change to the cloned directory, run:

    ```bash
    cd pepenet
    ```

* If you would like a specific [version/tag](https://github.com/pepenet-project/pepenet/tags), do a git checkout for that version. eg. 'v0.18.2.2'. If you don't care about the version and just want binaries from master, skip this step:

    ```bash
    git checkout v0.18.2.2
    ```

* If you are on a 64-bit system, run:

    ```bash
    make release-static-win64
    ```

* If you are on a 32-bit system, run:

    ```bash
    make release-static-win32
    ```

* The resulting executables can be found in `build/release/bin`

* **Optional**: to build Windows binaries suitable for debugging on a 64-bit system, run:

    ```bash
    make debug-static-win64
    ```

* **Optional**: to build Windows binaries suitable for debugging on a 32-bit system, run:

    ```bash
    make debug-static-win32
    ```

* The resulting executables can be found in `build/debug/bin`

### On FreeBSD:

The project can be built from scratch by following instructions for Linux above(but use `gmake` instead of `make`). 
If you are running pepenet in a jail, you need to add `sysvsem="new"` to your jail configuration, otherwise lmdb will throw the error message: `Failed to open lmdb environment: Function not implemented`.

pepenet is also available as a port or package as `pepenet-cli`.

### On OpenBSD:

You will need to add a few packages to your system. `pkg_add cmake gmake zeromq libiconv boost`.

The `doxygen` and `graphviz` packages are optional and require the xbase set.
Running the test suite also requires `py-requests` package.

Build pepenet: `env DEVELOPER_LOCAL_TOOLS=1 BOOST_ROOT=/usr/local gmake release-static`

Note: you may encounter the following error when compiling the latest version of pepenet as a normal user:

```
LLVM ERROR: out of memory
c++: error: unable to execute command: Abort trap (core dumped)
```

Then you need to increase the data ulimit size to 2GB and try again: `ulimit -d 2000000`

### On NetBSD:

Check that the dependencies are present: `pkg_info -c libexecinfo boost-headers boost-libs protobuf readline libusb1 zeromq git-base pkgconf gmake cmake | more`, and install any that are reported missing, using `pkg_add` or from your pkgsrc tree.  Readline is optional but worth having.

Third-party dependencies are usually under `/usr/pkg/`, but if you have a custom setup, adjust the "/usr/pkg" (below) accordingly.

Clone the pepenet repository recursively and checkout the most recent release as described above. Then build pepenet: `gmake BOOST_ROOT=/usr/pkg LDFLAGS="-Wl,-R/usr/pkg/lib" release`.  The resulting executables can be found in `build/NetBSD/[Release version]/Release/bin/`.

### On Solaris:

The default Solaris linker can't be used, you have to install GNU ld, then run cmake manually with the path to your copy of GNU ld:

```bash
mkdir -p build/release
cd build/release
cmake -DCMAKE_LINKER=/path/to/ld -D CMAKE_BUILD_TYPE=Release ../..
cd ../..
```

Then you can run make as usual.

### Building portable statically linked binaries

By default, in either dynamically or statically linked builds, binaries target the specific host processor on which the build happens and are not portable to other processors. Portable binaries can be built using the following targets:

* ```make release-static-linux-x86_64``` builds binaries on Linux on x86_64 portable across POSIX systems on x86_64 processors
* ```make release-static-linux-i686``` builds binaries on Linux on x86_64 or i686 portable across POSIX systems on i686 processors
* ```make release-static-linux-armv8``` builds binaries on Linux portable across POSIX systems on armv8 processors
* ```make release-static-linux-armv7``` builds binaries on Linux portable across POSIX systems on armv7 processors
* ```make release-static-linux-armv6``` builds binaries on Linux portable across POSIX systems on armv6 processors
* ```make release-static-win64``` builds binaries on 64-bit Windows portable across 64-bit Windows systems
* ```make release-static-win32``` builds binaries on 64-bit or 32-bit Windows portable across 32-bit Windows systems

### Cross Compiling

You can also cross-compile static binaries on Linux for Windows and macOS with the `depends` system.

* ```make depends target=x86_64-linux-gnu``` for 64-bit linux binaries.
* ```make depends target=x86_64-w64-mingw32``` for 64-bit windows binaries.
  * Requires: `python3 g++-mingw-w64-x86-64 wine1.6 bc`
* ```make depends target=x86_64-apple-darwin11``` for macOS binaries.
  * Requires: `cmake imagemagick libcap-dev librsvg2-bin libz-dev libbz2-dev libtiff-tools python-dev`
* ```make depends target=i686-linux-gnu``` for 32-bit linux binaries.
  * Requires: `g++-multilib bc`
* ```make depends target=i686-w64-mingw32``` for 32-bit windows binaries.
  * Requires: `python3 g++-mingw-w64-i686`
* ```make depends target=arm-linux-gnueabihf``` for armv7 binaries.
  * Requires: `g++-arm-linux-gnueabihf`
* ```make depends target=aarch64-linux-gnu``` for armv8 binaries.
  * Requires: `g++-aarch64-linux-gnu`
* ```make depends target=riscv64-linux-gnu``` for RISC V 64 bit binaries.
  * Requires: `g++-riscv64-linux-gnu`
* ```make depends target=x86_64-unknown-freebsd``` for freebsd binaries.
  * Requires: `clang-8`
* ```make depends target=arm-linux-android``` for 32bit android binaries
* ```make depends target=aarch64-linux-android``` for 64bit android binaries


The required packages are the names for each toolchain on apt. Depending on your distro, they may have different names. The `depends` system has been tested on Ubuntu 18.04 and 20.04.

Using `depends` might also be easier to compile pepenet on Windows than using MSYS. Activate Windows Subsystem for Linux (WSL) with a distro (for example Ubuntu), install the apt build-essentials and follow the `depends` steps as depicted above.

The produced binaries still link libc dynamically. If the binary is compiled on a current distribution, it might not run on an older distribution with an older installation of libc. Passing `-DBACKCOMPAT=ON` to cmake will make sure that the binary will run on systems having at least libc version 2.17.

## Running pepenetd

The build places the binary in `bin/` sub-directory within the build directory
from which cmake was invoked (repository root by default). To run in the
foreground:

```bash
./bin/pepenetd
```

To list all available options, run `./bin/pepenetd --help`.  Options can be
specified either on the command line or in a configuration file passed by the
`--config-file` argument.  To specify an option in the configuration file, add
a line with the syntax `argumentname=value`, where `argumentname` is the name
of the argument without the leading dashes, for example, `log-level=1`.

To run in background:

```bash
./bin/pepenetd --log-file pepenetd.log --detach
```

To run as a systemd service, copy
[pepenetd.service](utils/systemd/pepenetd.service) to `/etc/systemd/system/` and
[pepenetd.conf](utils/conf/pepenetd.conf) to `/etc/`. The [example
service](utils/systemd/pepenetd.service) assumes that the user `pepenet` exists
and its home is the data directory specified in the [example
config](utils/conf/pepenetd.conf).

If you're on Mac, you may need to add the `--max-concurrency 1` option to
pepenet-wallet-cli, and possibly pepenetd, if you get crashes refreshing.

## Internationalization

See [README.i18n.md](docs/README.i18n.md).

## Using Tor

> There is a new, still experimental, [integration with Tor](docs/ANONYMITY_NETWORKS.md). The
> feature allows connecting over IPv4 and Tor simultaneously - IPv4 is used for
> relaying blocks and relaying transactions received by peers whereas Tor is
> used solely for relaying transactions received over local RPC. This provides
> privacy and better protection against surrounding node (sybil) attacks.

While pepenet isn't made to integrate with Tor, it can be used wrapped with torsocks, by
setting the following configuration parameters and environment variables:

* `--p2p-bind-ip 127.0.0.1` on the command line or `p2p-bind-ip=127.0.0.1` in
  pepenetd.conf to disable listening for connections on external interfaces.
* `--no-igd` on the command line or `no-igd=1` in pepenetd.conf to disable IGD
  (UPnP port forwarding negotiation), which is pointless with Tor.
* `DNS_PUBLIC=tcp` or `DNS_PUBLIC=tcp://x.x.x.x` where x.x.x.x is the IP of the
  desired DNS server, for DNS requests to go over TCP, so that they are routed
  through Tor. When IP is not specified, pepenetd uses the default list of
  servers defined in [src/common/dns_utils.cpp](src/common/dns_utils.cpp).
* `TORSOCKS_ALLOW_INBOUND=1` to tell torsocks to allow pepenetd to bind to interfaces
   to accept connections from the wallet. On some Linux systems, torsocks
   allows binding to localhost by default, so setting this variable is only
   necessary to allow binding to local LAN/VPN interfaces to allow wallets to
   connect from remote hosts. On other systems, it may be needed for local wallets
   as well.
* Do NOT pass `--detach` when running through torsocks with systemd, (see
  [utils/systemd/pepenetd.service](utils/systemd/pepenetd.service) for details).
* If you use the wallet with a Tor daemon via the loopback IP (eg, 127.0.0.1:9050),
  then use `--untrusted-daemon` unless it is your own hidden service.

Example command line to start pepenetd through Tor:

```bash
DNS_PUBLIC=tcp torsocks pepenetd --p2p-bind-ip 127.0.0.1 --no-igd
```

A helper script is in contrib/tor/pepenet-over-tor.sh. It assumes Tor is installed
already, and runs Tor and pepenet with the right configuration.

### Using Tor on Tails

TAILS ships with a very restrictive set of firewall rules. Therefore, you need
to add a rule to allow this connection too, in addition to telling torsocks to
allow inbound connections. Full example:

```bash
sudo iptables -I OUTPUT 2 -p tcp -d 127.0.0.1 -m tcp --dport 18081 -j ACCEPT
DNS_PUBLIC=tcp torsocks ./pepenetd --p2p-bind-ip 127.0.0.1 --no-igd --rpc-bind-ip 127.0.0.1 \
    --data-dir /home/amnesia/Persistent/your/directory/to/the/blockchain
```

## Pruning

## Debugging

This section contains general instructions for debugging failed installs or problems encountered with pepenet. First, ensure you are running the latest version built from the GitHub repo.

### Obtaining stack traces and core dumps on Unix systems

We generally use the tool `gdb` (GNU debugger) to provide stack trace functionality, and `ulimit` to provide core dumps in builds which crash or segfault.

* To use `gdb` in order to obtain a stack trace for a build that has stalled:

Run the build.

Once it stalls, enter the following command:

```bash
gdb /path/to/pepenetd `pidof pepenetd`
```

Type `thread apply all bt` within gdb in order to obtain the stack trace

* If however the core dumps or segfaults:

Enter `ulimit -c unlimited` on the command line to enable unlimited filesizes for core dumps

Enter `echo core | sudo tee /proc/sys/kernel/core_pattern` to stop cores from being hijacked by other tools

Run the build.

When it terminates with an output along the lines of "Segmentation fault (core dumped)", there should be a core dump file in the same directory as pepenetd. It may be named just `core`, or `core.xxxx` with numbers appended.

You can now analyse this core dump with `gdb` as follows:

```bash
gdb /path/to/pepenetd /path/to/dumpfile`
```

Print the stack trace with `bt`

 * If a program crashed and cores are managed by systemd, the following can also get a stack trace for that crash:

```bash
coredumpctl -1 gdb
```

#### To run pepenet within gdb:

Type `gdb /path/to/pepenetd`

Pass command-line options with `--args` followed by the relevant arguments

Type `run` to run pepenetd

### Analysing memory corruption

There are two tools available:

#### ASAN

Configure pepenet with the -D SANITIZE=ON cmake flag, eg:

```bash
cd build/debug && cmake -D SANITIZE=ON -D CMAKE_BUILD_TYPE=Debug ../..
```

You can then run the pepenet tools normally. Performance will typically halve.

#### valgrind

Install valgrind and run as `valgrind /path/to/pepenetd`. It will be very slow.

### LMDB

Instructions for debugging suspected blockchain corruption as per @HYC

There is an `mdb_stat` command in the LMDB source that can print statistics about the database but it's not routinely built. This can be built with the following command:

```bash
cd ~/pepenet/external/db_drivers/liblmdb && make
```

The output of `mdb_stat -ea <path to blockchain dir>` will indicate inconsistencies in the blocks, block_heights and block_info table.

The output of `mdb_dump -s blocks <path to blockchain dir>` and `mdb_dump -s block_info <path to blockchain dir>` is useful for indicating whether blocks and block_info contain the same keys.

These records are dumped as hex data, where the first line is the key and the second line is the data.

# Known Issues

## Protocols

### Socket-based

Because of the nature of the socket-based protocols that drive pepenet, certain protocol weaknesses are somewhat unavoidable at this time. While these weaknesses can theoretically be fully mitigated, the effort required (the means) may not justify the ends. As such, please consider taking the following precautions if you are a pepenet node operator:

- Run `pepenetd` on a "secured" machine. If operational security is not your forte, at a very minimum, have a dedicated a computer running `pepenetd` and **do not** browse the web, use email clients, or use any other potentially harmful apps on your `pepenetd` machine. **Do not click links or load URL/MUA content on the same machine**. Doing so may potentially exploit weaknesses in commands which accept "localhost" and "127.0.0.1".
- If you plan on hosting a public "remote" node, start `pepenetd` with `--restricted-rpc`. This is a must.

### Blockchain-based

Certain blockchain "features" can be considered "bugs" if misused correctly. Consequently, please consider the following:

- When receiving pepenet, be aware that it may be locked for an arbitrary time if the sender elected to, preventing you from spending that pepenet until the lock time expires. You may want to hold off acting upon such a transaction until the unlock time lapses. To get a sense of that time, you can consider the remaining blocktime until unlock as seen in the `show_transfers` command.
