#!/usr/bin/env python3
# Copyright 2014 Canonical Ltd.
# Written by:
#   Zygmunt Krynicki <zygmunt.krynicki@canonical.com>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the the GNU General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the applicable version of the GNU General Public
# License for more details.
#.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# This file is part of Checkbox.

from setuptools import setup


setup(
    name="phablet",
    version="0.1",
    url="https://github.com/zyga/python-phablet",
    py_modules=['phablet'],
    author="Zygmunt Krynicki",
    author_email="zygmunt.krynicki@canonical.com",
    license="GPLv3",
    description="Python 2/3 API for Ubuntu Phablet",
    entry_points={
        'console_scripts': [
            'phablet=phablet:main',
        ],
    },
    zip_safe=True)
