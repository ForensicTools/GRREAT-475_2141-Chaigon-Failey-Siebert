GRREAT
===

### Installation
#### Windows
Download GRREAT and unpack it.
Download [ssdeep](http://ssdeep.sourceforge.net/#download) and unpack it.
`ssdeep.exe` should be in the same folder as [`find_by_hash.py`](https://github.com/pchaigno/GRREAT/blob/master/GRREAT/find_by_hash.py) (or in $PATH).

#### Linux
Install the dependencies:
```
$ sudo apt-get install python-pip python-dev libffi-dev libfuzzy-dev
$ sudo pip install ssdeep
```
Download GRREAT and unpack it.

### Find a file by its hash
The script will search for a file in the directory given by its hash.
```
$ python find_by_hash.py -h  /path/to/directory
97 - /path/to/directory/test_altered.jpg
100 - /path/to/directory/test_original.jpg
```

### Match against a list of hashes
The script will match hashes against hashes of the files in the directory given.
```
$ python find_by_hash.py -f NSLR.txt /path/to/directory/
100 - /path/to/directory/samples/XML/module.ivy
```
