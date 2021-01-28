Circcash integration/staging tree
================================


Copyright (c) 2009-2014 Bitcoin Developers

Copyright (c) 2011-2014 Litecoin Developers

Copyright (c) 2020 Joseph Van Name Ph.D.

What is Circcash?
----------------

Circcash is a fork of Bitcoin using Hashspin as a proof-of-work algorithm. Hashspin is designed to accelerate the development of reversible computing hardware. Hashspin is the only cryptocurrency mining algorithm that is designed to solve an extremely important scientific problem.
 - 2.0 minute block targets
 - 10 CIRCs per block
 - No subsidy halving
 - Supply increases linearly (to better advance science)
 - Mining reward remains constant
 - 2016 blocks to retarget difficulty
 - 12.5% of newly mined coins will be sent to a development fund. The development fund will be cut off after the following two conditions are BOTH met:

 1. The cryptocurrency has been out for four years, and
 
 2. The total number of 'hashes' computed for mining exceeds a threshold.

 - Forked from Litecoin v0.8.7.5

The Circcash development team may cut off the 12.5% funding early.

The rest is the same as Bitcoin/Litecoin.

See this link for the whitepaper: https://github.com/jvanname/Zammazazzer/blob/master/CirclefishICO.pdf

License
-------

Circcash is released under the terms of the MIT license. See `COPYING` for more
information or see http://opensource.org/licenses/MIT.


Installation
-------

Go to this link for instructions for installing Circcash on Ubuntu.

https://github.com/jvanname/circcash/blob/master/Ubuntu%20installation%20instructions



Development process
-------------------

Developers work in their own trees, then submit pull requests when they think
their feature or bug fix is ready.

If it is a simple/trivial/non-controversial change, then one of the Circcash
development team members simply pulls it.

If it is a *more complicated or potentially controversial* change, then the patch
submitter will be asked to start a discussion with the devs and community.

The patch will be accepted if there is broad consensus that it is a good thing.
Developers should expect to rework and resubmit patches if the code doesn't
match the project's coding conventions (see `doc/coding.txt`) or are
controversial.

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/circcash-project/circcash/tags) are created
regularly to indicate new official, stable release versions of Circcash.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test. Please be patient and help out, and
remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write unit tests for new code, and to
submit new unit tests for old code.

Unit tests for the core code are in `src/test/`. To compile and run them:

    cd src; make -f makefile.unix test

Unit tests for the GUI code are in `src/qt/test/`. To compile and run them:

    qmake BITCOIN_QT_TEST=1 -o Makefile.test bitcoin-qt.pro
    make -f Makefile.test
    ./circcash-qt_test

