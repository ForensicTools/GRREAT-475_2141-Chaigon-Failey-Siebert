GRREAT
===

GRREAT is a tool written in Python that will integrate with Google GRR.
It will allow the user to hash the contents of a box with a piecewise algorithm and store the hashes.
The user could later hash the contents again to determine what has been changed and the extent of those changes.

[The discussion for the integration of this feature in GRR](https://groups.google.com/forum/#!topic/grr-dev/VB13CEzVukE) is on the dev forum.

### Using GRREAT
In order to utilize this tool, the user will need to download and install a few dependancies. 
-[Python 2.7](https://www.python.org/downloads/release/python-279/)
-[SSDeep](https://pypi.python.org/pypi/ssdeep)


### GRR
[GRR](https://github.com/google/grr) (for GRR Rapid Response) is an incident response framework focused on remote live forensics.
The [AsciiDoc documentation](https://github.com/google/grr-doc) is hosted in a separate repository.
GRR uses the [Google Python Style conventions](https://google-styleguide.googlecode.com/svn/trunk/pyguide.html).


### Piecewise hashing in Python
Two Python wrappers for *ssdeep* already exist -- used for reference:
- [python-ssdeep](https://github.com/DinoTools/python-ssdeep) - LGPLv3
- [pyssdeep](https://code.google.com/p/pyssdeep/) - BSD New


### Contributors
- Paul Chaignon &lt;paul.chaignon@gmail.com&gt;
- Kirstie Failey &lt;klf9481@rit.edu&gt;
- Andrea Siebert &lt;ans9281@rit.edu&gt;

