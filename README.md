# Byeongal Static Report
Byeongal Static Report is an automated static analysis open source software. You can get a report( [md5.json](./7d148e220040de2fae1439fbc0e783ef344dceaea4757611722d8378a4938d0b.json) ) which contains following informatioin:
* File Hash Information
* File Magic
* String
* PE File Information
* Fuzzy Hash
## Preconfiguration
To use **Byeongal Static Report**, you have to install following python modules.
```bash
$ pip3 install pefile
$ pip3 install python-magic 
$ pip3 install yara-python
$ pip3 install ssdeep
$ pip3 install simplejson
$ pip3 install M2Crypto
```
## Usage
```bash
$ python3 byeongal_static.py <file_path> 
```

## Tested On
* Ubuntu 16.04 LTS
* Python 3.5.2

## Reference
To create this software, I refer to the following software:
* [PEframe 5.0.1](https://github.com/guelfoweb/peframe)
* [TLSH](https://github.com/trendmicro/tlsh)
* [pefile](https://github.com/erocarrera/pefile)
* [python-magic](https://github.com/ahupp/python-magic)
* [yara-python](https://github.com/VirusTotal/yara-python)
* [ssdeep Python Wrapper](https://github.com/DinoTools/python-ssdeep)
## Contact
If you want to contact me, please send me an email to my email address(corea_kyj@naver.com).
* Ps. I can understand only English and Korean and prefer to use Korean.

## License
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
