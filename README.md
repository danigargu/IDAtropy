# IDAtropy

IDAtropy is a plugin for Hex-Ray's IDA Pro designed to generate charts of entropy and histograms using the power of idapython and matplotlib.

## DEPENDENCIES

IDAtropy requires the matplotlib python's library. Personally, I prefer the following steps to install it, that not requiere compile Numpy:

* Download the lasted numpy .whl from: http://www.lfd.uci.edu/~gohlke/pythonlibs/#numpy
* Install with pip: 
    * IDA <= 6.9: `pip install numpy-1.13.3+mkl-cp27-cp27m-win32.whl`
    * IDA >= 7.0 (for python x64): `pip install numpy-1.13.3+mkl-cp27-cp27m-win_amd64.whl`
* Finally, install matplotlib: `pip install matplotlib`

The plugin was only extensively tested on IDA Pro 6.9 and 7.0 for Windows/Mac, with Python 2.7 and matplotlib 1.4.3, but it should work with other versions and OS's. If you find any inconsistency, let me know.

## INSTALLATION

Simply, copy `IDAtropy.py` to the IDA's plugins folder.

## SCREENSHOTS

##### Plugin options
![Snapshot1](https://user-images.githubusercontent.com/1675387/35856350-0c473678-0b36-11e8-9f84-3f5dbcd03522.png "Plugin options")
##### Entropy - All segments
![Snapshot2](https://user-images.githubusercontent.com/1675387/35856299-e5bed790-0b35-11e8-9d55-b75cfdf94556.png "Entropy - All segments")
##### Histogram
![Snapshot3](https://user-images.githubusercontent.com/1675387/35856690-07d9ddba-0b37-11e8-9445-7b2765cca446.png "Histogram")
##### Entropy on-click
![Snapshot4](https://user-images.githubusercontent.com/1675387/35856708-18d7a340-0b37-11e8-9643-9cf51a74a4d6.png "Entropy on-click")
##### Xrefs finder
![Snapshot5](https://user-images.githubusercontent.com/1675387/35856738-2e5bf2b6-0b37-11e8-9526-5e4908c49ac3.png "Xrefs")


## CONTACT

Any comment or pull request will be highly appreciated :-)

