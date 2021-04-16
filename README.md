# IDAtropy

IDAtropy is a plugin for Hex-Ray's IDA Pro designed to generate charts of entropy and histograms using the power of idapython and matplotlib.

## DEPENDENCIES

IDAtropy requires the matplotlib python library:
```
pip install matplotlib
```

The current version of IDAtropy only runs in Python 3.X and IDA >= 7.4. If you want an older version with support for Python 2.X and IDA < 7.4, [check this release](https://github.com/danigargu/IDAtropy/releases/tag/python2).

## INSTALLATION

Simply, copy `IDAtropy.py` to the IDA's plugins folder.

To install just for the current user, copy the file into one of these directories:

| OS          | Plugin path                          |
| ----------- | ------------------------------------ |
| Linux/macOS | `~/.idapro/plugins`                  |
| Windows     | `%AppData%\Hex-Rays\IDA Pro\plugins` |

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

