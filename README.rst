Python API for Ubuntu Phablet
=============================

Example::

    import phablet
    phablet = phablet.Phablet()
    retval = phablet.run('false')

You can use the phablet module to run batch commands:

    python3 -m phablet uname -a

As well as for interactive sessions:

    python3 -m phablet
