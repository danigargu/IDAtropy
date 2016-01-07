# IDAtropy

IDAtropy is a plugin for Hex-Ray's IDA Pro designed to generate charts of entropy and histograms using the power of idapython and matplotlib.

## DEPENDENCIES

IDAtropy requires the matplotlib python's library. Personally, I prefer the following steps to install it, that not requiere compile Numpy:

*  Download the lasted numpy .whl from: http://www.lfd.uci.edu/~gohlke/pythonlibs/#numpy
*  Install with pip: pip install numpy-1.9.3+mkl-cp27-none-win32.whl
*  Finally, install matplotlib: pip install matplotlib

The plugin was only extensively tested on IDA Pro <= 6.9 for Windows, with Python 2.7 and matplotlib 1.4.3, but it should work with other versions and OS's. If you find any inconsistency, let me know.

## INSTALLATION

Simply, copy `IDAtropy.py` to the IDA's plugins folder.

## SCREENSHOTS

##### Plugin options
![Snapshot1](https://cloud.githubusercontent.com/assets/1675387/11427089/b6e1f0cc-9460-11e5-9650-a9c839c9dbe4.png "Plugin options")
##### Entropy - disk binary
![Snapshot2](https://cloud.githubusercontent.com/assets/1675387/11427091/ba1389e0-9460-11e5-876b-3238852718d3.png "Entropy - disk binary")
##### Histogram - disk binary
![Snapshot3](https://cloud.githubusercontent.com/assets/1675387/11427094/bb942edc-9460-11e5-9853-4db29f36724a.png "Histogram - disk binary")
##### Entropy on-click
![Snapshot3](https://cloud.githubusercontent.com/assets/1675387/11427096/bd03ce58-9460-11e5-9a4a-501e5a6efe4d.png "Entropy on-click")

## CONTACT

Any comment or request will be highly appreciated :-)


