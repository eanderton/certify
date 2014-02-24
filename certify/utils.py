__authors__ = ['"Seth Vidal" <skvidal@fedoraproject.org>', '"Hans Lellelid" <hans@xmpl.org>']
__copyright__ = "Copyright (c) 2007 Red Hat, inc"
__license__ = """This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Library General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
"""

import os
import string
import sys
import traceback
import socket
import glob
import optparse
import logging
import subprocess

from certify import __version__, exc

# The standard I/O file descriptors are redirected to /dev/null by default.
if (hasattr(os, "devnull")):
    REDIRECT_TO = os.devnull
else:
    REDIRECT_TO = "/dev/null"

def get_version_str():
    import OpenSSL
    import certify
    return "Certify v%s - pyOpenSSL v%s" % (certify.__version__, OpenSSL.__version__)

def trace_me():
    x = traceback.extract_stack()
    bar = string.join(traceback.format_list(x))
    return bar

def daemonize(pidfile=None):
    """
    Daemonize this process with the UNIX double-fork trick.
    Writes the new PID to the provided file name if not None.
    """

    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.chdir("/")
    os.setsid()
    os.umask(077)
    pid = os.fork()

    os.close(0)
    os.close(1)
    os.close(2)

    # based on http://code.activestate.com/recipes/278731/
    os.open(REDIRECT_TO, os.O_RDWR)     # standard input (0)

    os.dup2(0, 1)                       # standard output (1)
    os.dup2(0, 2)                       # standard error (2)


    if pid > 0:
        if pidfile is not None:
            open(pidfile, "w").write(str(pid))
        sys.exit(0)

def get_hostname(talk_to_certify=True):
    """"
    localhost" is a lame hostname to use for a key, so try to get
    a more meaningful hostname. We do this by connecting to the certify
    and seeing what interface/ip it uses to make that connection, and looking
    up the hostname for that.
    """
    hostname = socket.gethostname()
    # print "DEBUG: HOSTNAME TRY1: %s" % hostname
    try:
        ip = socket.gethostbyname(hostname)
    except:
        return hostname
    if ip != "127.0.0.1":
        return hostname

def run_triggers(ref, globber):
    """
    Runs all the trigger scripts in a given directory.
    ref can be a certify object, if not None, the name will be passed
    to the script.  If ref is None, the script will be called with
    no argumenets.  Globber is a wildcard expression indicating which
    triggers to run.  Example:  "/var/lib/certify/triggers/blah/*"
    """

    log = logging.getLogger('%s.triggers' % __name__)
    triggers = glob.glob(globber)
    triggers.sort()
    for file in triggers:
        log.debug("Executing trigger: %s" % file)
        try:
            if file.find(".rpm") != -1:
                # skip .rpmnew files that may have been installed
                # in the triggers directory
                continue
            if ref:
                rc = subprocess.call(file, ref, shell=False)
            else:
                rc = subprocess.call(file, shell=False)
        except:
            log.warning("Warning: failed to execute trigger: %s" % file, exc_info=True)
            continue

        if rc != 0:
            raise exc.TriggerFailed("certify trigger failed: %(file)s returns %(code)d" % { "file" : file, "code" : rc })


class CertmasterOptionParser(optparse.OptionParser):
    def get_version(self):
        return __version__
