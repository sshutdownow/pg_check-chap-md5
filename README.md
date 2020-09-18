# pg_check-chap-md5

pg_check-chap-md5 is [PostgreSQL](https://www.postgresql.org/) extension that implements function that check authentication via CHAP MD5 [rfc1994](https://tools.ietf.org/html/rfc1994).
Previously I have a such function in [perl](https://github.com/sshutdownow/pg_check-chap-md5/blob/master/check_chapmd5_password_perl.sql). But perl adds about 20Megs to every postgresql proccess. It was the only one function in perl, so, I have decided to rewrite it in C. After it, RADIUS server performs much better, especially under heavy load.

Installation
------------
1. Download and unpack.
2. Compile source code, to fullfill it for RedHat/CentOS postgresql-devel package is required (yum install postgresql-devel), for Debian/Ubuntu you should install postgresql-server-dev package (apt-get install postgresql-server-dev):
make
3. Install:
sudo make install
4. Register extension in PostgreSQL:
CREATE EXTENSION check_chapmd5_password;

Usage:
------
boolean check_chapmd5_password(text chap_password, text chap_challenge, text clear_password);
Where chap_password and chap_challenge strings are encoded in hex.

### Copyright

  Copyright (c) 2017 Igor Popov

License
-------
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

### Authors

  Igor Popov
  (ipopovi |at| gmail |dot| com)
