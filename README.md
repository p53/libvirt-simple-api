Installation:
=========

  Compatible with python3

  **Download source:**

    git clone URL /opt/libvirt-simple-api

  **Install virtualenv:**

    pip install virtualenv

  **Setup virtual environment:**

    cd /opt/libvirt-simple-api
    virtualenv --no-site-packages venv

  **Activate virtual environment:**

    source venv/bin/activate

  **Install dependencies:**

  required python packages also required some C headers/libs, you must install them prior installing python modules.

  install C headers/lib (names of OS packages vary, depending on distro):

  * python devel
  * openssl
  * openssl-dev


  then install python modules:

    ```
    pip3 install -r requirements.txt
    ```

  **DHCP server:**

  this api uses (if enabled in config) DHCP server api - called OMAPI to get IP of VM's

  in case they don't have guest agent installed, thus you need enable OMAPI on DHCP server e.g.:

    ```
    key omapi_key {
         algorithm hmac-md5;
         secret Ofakekeyfakekeyfakekey==;
    }

    omapi-port 7911;
    omapi-key omapi_key;
    ```

  **NOTE:** Generate your own private key and certificate, those included are for demo purposes!!

Usage:
=========

#### Examples

  This will run api server:

    /opt/libvirt-simple-api/libvirt-simple-api.py

### Credits:

  __Author: Pavol Ipoth__

### Copyright:

  __License: GPLv3__
