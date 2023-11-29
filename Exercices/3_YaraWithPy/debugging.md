# Ubuntu 22.04 Problem 

problème d'installation avec le "pip install yara-python" en cas de refus "python3 -m pip install yara-python" mais ça fonctionne avec ça : 

```bash
$ git clone --recursive https://github.com/VirusTotal/yara-python
$ cd yara-python
$ python setup.py build
$ sudo python setup.py install
```


