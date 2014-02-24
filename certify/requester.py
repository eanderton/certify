"""
Module contains support methods for requesting certificates.
"""

__authors__ = [
    '"Seth Vidal" <skvidal@fedoraproject.org>',
    '"Hans Lellelid" <hans@xmpl.org>',
    '"Eric Anderton" <eric.t.anderton@gmail.com'
]
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
import logging
import os
import sys
import xmlrpclib
import socket
import time

from certify.config import minion_config
from certify import utils, exc, certs

logger = lambda: logging.getLogger(__name__)

def request_cert(hostname=None):
    # this should be enough, but do we want to allow parameters
    # for overriding the server and port from the config file?
    # maybe not. -- mpd
    create_minion_keys(hostname)

def create_minion_keys(CN, C=None, ST=None, L=None, O=None, OU=None, emailAddress=None, hashalgorithm='sha1'):
    """
    """
    log = logger()
    
    cert_dir = minion_config.cert_dir
    master_uri = 'http://%s:%s/' % (minion_config.certify, minion_config.certify_port)

    filename = CN
    if filename is None:
        filename = utils.get_hostname()
        if filename is None:
            raise exc.CMException("Could not determine a hostname other than localhost")
            
    # use lowercase letters for filenames
    filename = filename.lower()
    # XXX: Other normalization?

    # TODO: Make the extensions configurable?
    key_file = '%s/%s.pem' % (cert_dir, filename)
    csr_file = '%s/%s.csr' % (cert_dir, filename)
    cert_file = '%s/%s.cert' % (cert_dir, filename)
    ca_cert_file = '%s/ca.cert' % cert_dir

    if os.path.exists(cert_file) and os.path.exists(ca_cert_file):
        log.debug("cert file already exists: %s" % cert_file)
        return

    keypair = None
    try:
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
            
        force_recreate_csr = False
        
        if os.path.exists(key_file):
            keypair = certs.retrieve_key_from_file(key_file)
        else:
            keypair = certs.make_keypair()
            certs.dump_to_file(keypair, key_file, mode=0600)
            force_recreate_csr = True
            
        if not os.path.exists(csr_file) or force_recreate_csr:
            csr = certs.make_csr(keypair, CN=CN, C=C, ST=ST, L=L, O=O, OU=OU, emailAddress=emailAddress, hashalgorithm=hashalgorithm)
            certs.dump_to_file(csr, csr_file, mode=0644)
            
    except object as e:
        log.exception(e)
        log.exception("Could not create local keypair or csr for session.")
        raise exc.CMException("Could not create local keypair or csr for session")

    result = False

    while not result:
        try:
            log.debug("submitting CSR: %s  to certify %s" % (csr_file, master_uri))
            (result, cert_string, ca_cert_string) = submit_csr_to_master(csr_file, master_uri)
        except socket.error:
            log.warning("Could not connect to server at %s" % master_uri, exc_info=True)
            
        if not result:
            log.warning("no response from certify %s, sleeping 10 seconds" % master_uri)
            time.sleep(10)

    if result:
        log.debug("received certificate from certify %s, storing to %s" % (master_uri, cert_file))
        if not keypair:
            keypair = certs.retrieve_key_from_file(key_file)
        valid = certs.check_cert_key_match(cert_string, keypair)
        if not valid:
            log.info("certificate does not match key (run certify-ca --clean first?)")
            sys.stderr.write("certificate does not match key (run certify-ca --clean first?)\n")
            return
        
        cert_fd = os.open(cert_file, os.O_RDWR|os.O_CREAT, 0644)
        os.write(cert_fd, cert_string)
        os.close(cert_fd)

        ca_cert_fd = os.open(ca_cert_file, os.O_RDWR|os.O_CREAT, 0644)
        os.write(ca_cert_fd, ca_cert_string)
        os.close(ca_cert_fd)

def submit_csr_to_master(csr_file, master_uri):
    """"
    gets us our cert back from the certify.wait_for_cert() method
    takes csr_file as path location and master_uri
    
    :returns Bool, str(cert), str(ca_cert)
    :rtype: tuple
    """
    fo = open(csr_file)
    csr = fo.read()
    s = xmlrpclib.ServerProxy(master_uri)
    return s.wait_for_cert(csr)
