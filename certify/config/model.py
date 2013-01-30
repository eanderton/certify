"""
Model that describes expected certmaster server/minion configuration.
"""

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

from certify.config.parser import BaseConfig, BoolOption, IntOption, Option

class CMConfig(BaseConfig):
    log_level = Option('INFO')
    listen_addr = Option('')
    listen_port = IntOption(51235)
    pid_file = Option('/var/run/certmaster.pid')
    
    ca_cn = Option('%(hostname)s-CA-KEY')
    cadir = Option('/etc/pki/certmaster/ca')
    
    cert_dir = Option('/etc/pki/certmaster')
    certroot =  Option('/var/lib/certmaster/certmaster/certs')
    csrroot = Option('/var/lib/certmaster/certmaster/csrs')
    cert_extension = Option('cert')
    
    autosign = BoolOption(False)
    sync_certs = BoolOption(False)
    peering = BoolOption(True)
    peerroot =  Option('/var/lib/certmaster/peers')

class MinionConfig(BaseConfig):
    log_level = Option('INFO')
    certmaster = Option('certmaster')
    certmaster_port = IntOption(51235)
    cert_dir = Option('/etc/pki/certmaster')

class MinionReqConfig(BaseConfig):
    """
    Configuration for the CSR.
    """
    key_bits = IntOption(2048)
    subj_countryName = Option(None)
    subj_stateOrProvinceName = Option(None)
    subj_localityName = Option(None)
    subj_organizationName = Option(None)
    subj_organizationalUnitName = Option(None)
    subj_commonName = Option(None)
    subj_emailAddress = Option(None)