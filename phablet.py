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
"""
:mod:`phablet` -- Ubuntu Phablet API
====================================

This module provides a very simple synchronous command execution interface for
the Ubuntu Phablet (phone and tablet)

Example:

    phablet = Phablet()
    retval = phablet.run('false')

You can also use phablet as an executable:

    python3 -m phablet --help
"""

from gettext import gettext as _
import argparse
import logging
import os
import subprocess

__version__ = "0.1"

_logger = logging.getLogger("phablet")


class PhabletError(Exception):
    """
    Base class for all phablet exceptions
    """


class UnableToStartSSH(PhabletError):
    """
    Exception raised when ssh cannot be started on the phablet device
    """

    def __str__(self):
        return _("Unable to start SSH on the phablet device")


class PortForwardingError(PhabletError):
    """
    Exception raised TCP port forwarding between the tablet and the local
    machine cannot be established
    """

    def __str__(self):
        return _("Unable to setup port forwarding to the phablet device")


class DeviceNotDetected(PhabletError):
    """
    Exception raised when the phablet device is not connected or not turned on
    """

    def __str__(self):
        return _("No phablet devices detected")


class MultipleDevicesDetected(PhabletError):
    """
    Exception raised when multiple devices are connected and :class:`Phablet`
    is constructed without passing a specific device serial number.
    """

    def __str__(self):
        return _("Multiple phablet devices detected")


class UnableToPurgeKnownSSHHost(PhabletError):
    """
    Exception raised when ~/.ssh/known_hosts entry for the phablet cannot
    be purged.
    """

    def __str__(self):
        return _(
            "Unable to purge phablet device entry from ~/.ssh/known_hosts")


class UnableToCopySSHKey(PhabletError):
    """
    Exception raised when local public ssh key cannot be copied over as a know
    authorized key onto the phablet device
    """

    def __str__(self):
        return _("Unable to copy public ssh key over to the phablet device")


class NoPublicKeysFound(PhabletError):
    """
    Exception raised when there are no public keys that can be used to
    authorize the connection to a phablet device
    """

    def __str__(self):
        return _("No public ssh keys found on the local account")


class Phablet:
    """
    Pythonic interface to the Ubuntu Phablet
    """

    def __init__(self, serial=None):
        """
        Initialize a new Phablet device.

        :param serial:
            serial number of the phablet device to talk to

        Note that if you don't specify the serial number and the user happens
        to have more than one device connected then :meth:`run()` will raise
        :class:`MultipleDevicesDetected`.
        """
        self._serial = serial
        self._port = None

    @property
    def serial(self):
        """
        serial number of the device (or None)
        """
        return self._serial

    @property
    def port(self):
        """
        local tcp port where phablet ssh is exposed

        This is None if ssh port forwarding was not established yet
        """
        return self._port

    def run(self, cmd, timeout=None, key=None):
        """
        Run a command on the phablet device using ssh

        :param cmd:
            a list of strings to execute as a command
        :param timeout:
            a timeout (in seconds) for device discovery
        :param key:
            a path to a public ssh key to use for connection
        :returns:
            the exit code of the command
        """
        if not isinstance(cmd, list):
            raise TypeError("cmd needs to be a list")
        if not all(isinstance(item, str) for item in cmd):
            raise TypeError("cmd needs to be a list of strings")
        self._wait_for_device(timeout)
        self._setup_port_forwarding()
        self._purge_known_hosts_entry()
        self._copy_ssh_key(key)
        return self._run_ssh(cmd)

    def _invoke_adb(self, cmd, *args, **kwargs):
        env = os.environ
        if self._serial is not None:
            env['ANDROID_SERIAL'] = self._serial
        _logger.debug("Invoking adb: %r", cmd)
        return subprocess.check_call(
            cmd, *args, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, **kwargs)

    def _wait_for_device(self, timeout):
        _logger.info("Waiting for device")
        if hasattr(subprocess, "TimeoutExpired"):
            try:
                self._invoke_adb(['adb', 'wait-for-device'], timeout=timeout)
            except subprocess.TimeoutExpired:
                raise DeviceNotDetected
            except subprocess.CalledProcessError:
                if self._serial is None:
                    raise MultipleDevicesDetected
                else:
                    raise DeviceNotDetected
        else:
            if timeout is not None:
                raise ValueError("timeout is not supported on python2.x")
            try:
                self._invoke_adb(['adb', 'wait-for-device'])
            except subprocess.CalledProcessError:
                if self._serial is None:
                    raise MultipleDevicesDetected
                else:
                    raise DeviceNotDetected

    def _setup_port_forwarding(self):
        if self._port is not None:
            return
        _logger.info("Starting ssh on the device")
        try:
            self._invoke_adb(['adb', 'shell', 'start', 'ssh'])
        except subprocess.CalledProcessError:
            raise UnableToStartSSH
        _logger.info("Setting up port forwarding")
        for port in range(2222, 2299):
            try:
                subprocess.check_call([
                    'adb', 'forward', 'tcp:{0}'.format(port), 'tcp:22'])
            except subprocess.CalledProcessError:
                continue
            else:
                self._port = port
                break
        else:
            raise PortForwardingError

    def _purge_known_hosts_entry(self):
        assert self._port is not None
        _logger.info("Purging ~/.ssh/known_hosts entry")
        try:
            _logger.debug
            subprocess.check_call([
                'ssh-keygen', '-f', os.path.expanduser('~/.ssh/known_hosts'),
                '-R', '[localhost]:{0}'.format(self._port)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            raise UnableToPurgeKnownSSHHost

    def _find_public_key(self):
        _logger.info("Looking for a public ssh key")
        candidates = []
        ssh_dir = os.path.expanduser('~/.ssh/')
        for filename in os.listdir(ssh_dir):
            ssh_key = os.path.join(ssh_dir, filename)
            if os.path.isfile(ssh_key) and filename.endswith('.pub'):
                candidates.append(ssh_key)
        # Sort the keys by modification time, pick the most recent key
        candidates.sort(key=lambda f: os.stat(f).st_mtime, reverse=True)
        _logger.debug("Available ssh public keys: %r", candidates)
        if candidates:
            return candidates[0]

    def _copy_ssh_key(self, key):
        if key is None:
            key = self._find_public_key()
        if key is None:
            raise NoPublicKeysFound
        _logger.info("Setting up SSH connection using key: %s", key)
        try:
            self._invoke_adb([
                'adb', 'push', key, '/home/phablet/.ssh/authorized_keys'])
            self._invoke_adb([
                'adb', 'shell', 'chown', 'phablet:phablet', '-R',
                '/home/phablet/.ssh/'])
            self._invoke_adb([
                'adb', 'shell', 'chmod', '700', '/home/phablet/.ssh'])
            self._invoke_adb([
                'adb', 'shell', 'chmod', '600',
                '/home/phablet/.ssh/authorized_keys'])
        except subprocess.CalledProcessError:
            raise UnableToCopySSHKey

    def _run_ssh(self, cmd):
        assert self._port is not None
        ssh_cmd = ['ssh']
        for opt in self._get_ssh_options():
            ssh_cmd.append('-o')
            ssh_cmd.append(opt)
        ssh_cmd.extend(['phablet@localhost', '--'])
        ssh_cmd.extend(cmd)
        return subprocess.call(ssh_cmd)

    def _get_ssh_options(self):
        return [
            'CheckHostIP=no',
            'StrictHostKeyChecking=no',
            'UserKnownHostsFile=/dev/null',
            'LogLevel=quiet',
            'KbdInteractiveAuthentication=no',
            'PasswordAuthentication=no',
            'Port={0}'.format(self._port),
        ]


def main(args=None):
    """
    Phablet command line user interface

    This function implements the phablet command line tool
    """
    parser = argparse.ArgumentParser(
        description=_("Run a command on Ubuntu Phablet"),
        epilog="""
        This tool will start ssh on your connected Ubuntu Touch device, forward
        a local port to the device, copy your ssh id down to the device (so you
        can log in without a password), and then ssh into the device through
        the locally forwarded port.

        This results in a very nice shell, which for example can display the
        output of 'top' at the correct terminal size, rather than being stuck
        at 80x25 like 'adb shell'

        Like ssh-copy-id, this script will push down the newest ssh key it can
        find in ~/.ssh/*.pub, so if you find the wrong key being pushed down,
        simply use 'touch' to make your desired key the newest one, and then
        this script will find it.
        """)
    dev_group = parser.add_argument_group(_("device connection options"))
    dev_group.add_argument(
        '-s', '--serial', action='store',
        help=_('connect to the device with the specified serial number'),
        default=None)
    if hasattr(subprocess, 'TimeoutExpired'):
        dev_group.add_argument(
            '-t', '--timeout', type=float, default=30.0,
            help=_('timeout for device discovery'))
    else:
        dev_group.add_argument(
            '-t', '--timeout', type=float, default=None,
            help=argparse.SUPPRESS)
    dev_group.add_argument(
        '-k', '--public-key', action='store', default=None,
        help=_('use the specified public key'))
    log_group = parser.add_argument_group(_("logging options"))
    log_group.add_argument(
        '--verbose', action='store_const', dest='log_level',
        const='INFO', help=_('be more verbose during connection set-up'))
    log_group.add_argument(
        '--log-level', action='store',
        help=_('set log level (for debugging)'),
        choices=[
            logging.getLevelName(level)
            for level in [
                logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR,
                logging.CRITICAL]])
    parser.add_argument(
        'cmd', nargs='...',
        help=_('command to run on the phablet, '
               ' if left out an interactive shell is started'))
    parser.add_argument('--version', action='version', version=__version__)
    parser.set_defaults(log_level='WARNING')
    ns = parser.parse_args(args)
    try:
        # Py3k
        level = logging._nameToLevel[ns.log_level]
    except AttributeError:
        # Py27
        level = logging._levelNames[ns.log_level]
    logging.basicConfig(
        level=level, style='{', format="[{levelname:10}] {message}")
    try:
        phablet = Phablet(ns.serial)
        return phablet.run(ns.cmd, timeout=ns.timeout, key=ns.public_key)
    except PhabletError as exc:
        _logger.critical("%s", exc)
        return 255


if __name__ == "__main__":
    raise SystemExit(main())
