"""
Application to request a cert from a certify CertMaster.
Takes no arguments, uses /etc/certify/minion.conf

Copyright 2008, Red Hat, Inc
Michael DeHaan <mdehaan@redhat.com>

This software may be freely redistributed under the terms of the GNU
general public license.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
"""
import optparse
import logging
from certify import requester

def main():
    parser = optparse.OptionParser()

    parser.add_option('--hostname', action="store", dest="hostname",
        metavar="NAME", 
        help='hostname to use as the CN for the certificate')
    
    (opts, args) = parser.parse_args()
    
    logging.basicConfig()    
    logger = logging.getLogger(__name__)

    requester.request_cert(hostname=opts.hostname)
