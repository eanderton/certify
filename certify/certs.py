"""
Functions for creating and loading cert/key material.
"""
import os
import socket

from OpenSSL import crypto, SSL

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

def make_keypair(algorithm=crypto.TYPE_RSA, numbits=2048):
    """
    Create a new keypair of specified algorithm and number of bits.
    
    :param algorithm: The crypto algorithm (crypto.TYPE_RSA or crypto.TYPE_DSA) 
    :param numbits: Number of bits for the key.
    """
    pkey = crypto.PKey()
    pkey.generate_key(algorithm, numbits)
    return pkey

def make_csr(pkey, CN, C=None, ST=None, L=None, O=None, OU=None, emailAddress=None, hashalgorithm='sha1'):
    """
    Creates a certificate signing request (CSR) given the specified subject attributes.
    
    :param CN: commonName; this is typically hostname for server cert applications.
    :param C: countryName
    :param ST: stateOrProvinceName
    :param L:  localityName
    :param O: organizationName
    :param OU: organizationalUnitName
    :param emailAddress: The email address for the certifificate. 
    :return: The :class:`OpenSSL.crypto.X509Req` instance.
    """
    req = crypto.X509Req()
    req.get_subject()
    subj  = req.get_subject()
    subj.C = C
    subj.ST = ST
    subj.L = L
    subj.O = O
    subj.OU = OU
    subj.CN = CN
    subj.emailAddress = emailAddress
    req.set_pubkey(pkey)
    req.sign(pkey, hashalgorithm)
    return req

def create_ca(CN, C=None, ST=None, L=None, O=None, OU=None, emailAddress=None, hashalgorithm='sha1'):
    """
    :param CN: commonName; this is typically hostname for server cert applications.
    :param C: countryName
    :param ST: stateOrProvinceName
    :param L:  localityName
    :param O: organizationName
    :param OU: organizationalUnitName
    :param emailAddress: The email address for the certifificate. 
    :return: The :class:`OpenSSL.crypto.X509Req` instance.
    """
    # TODO: Refactor, refactor.
    cakey = make_keypair()
    careq = make_csr(cakey, cn=CN)
    cacert = crypto.X509()
    cacert.set_serial_number(0)
    cacert.gmtime_adj_notBefore(0)
    cacert.gmtime_adj_notAfter(60*60*24*365*10) # 10 yrs - hard to beat this kind of cert!
    cacert.set_issuer(careq.get_subject())
    cacert.set_subject(careq.get_subject())
    cacert.set_pubkey(careq.get_pubkey())
    cacert.set_version(2)
    
    extensions = []
    # In case, you're wondering, param 2 is "critical?"
    extensions.append(crypto.X509Extension('basicConstraints', True,'CA:TRUE'))
    extensions.append(crypto.X509Extension('subjectKeyIdentifier' , True , 'hash'))
    extensions.append(crypto.X509Extension('authorityKeyIdentifier' , False, 'keyid:always,issuer:always'))
    
    cacert.add_extensions(extensions)
    cacert.sign(cakey, 'sha1')
    return cacert

def _get_serial_number(cadir):
    serial = '%s/serial.txt' % cadir
    i = 1
    if os.path.exists(serial):
        with open(serial, 'r') as fp:
            f = fp.read()
        f = f.replace('\n','')
        try:
            i = int(f)
            i += 1
        except ValueError:
            i = 1

    _set_serial_number(cadir, i)
    return i


def _set_serial_number(cadir, last):
    serial = '%s/serial.txt' % cadir
    with open(serial, 'w') as fp:
        fp.write(str(last) + '\n')

def create_slave_certificate(csr, cakey, cacert, cadir):
    """
    Create a new slave cert.
    
    :param csr: The request for the slave cert.
    :type csr: :class:`OpenSSL.crypto.X509Req`
    
    :param cakey: The CA key that will sign this slave cert.
    :type cakey: :class:`OpenSSL.crypto.PKey`
    
    :param cacert: The CA certificate that will sign this slave cert. 
    :type cacert: :class:`OpenSSL.crypto.X509`
    
    :param cadir: The directory for the CA database.
    :type cadir: str
    """
    cert = crypto.X509()
    cert.set_serial_number(_get_serial_number(cadir))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60*60*24*365*10) # 10 yrs - hard to beat this kind of cert!
    cert.set_issuer(cacert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.set_version(2)
    
    extensions = []
    extensions.append(crypto.X509Extension('basicConstraints', False ,'CA:FALSE'))
    
    # XXX: What *should* these be for the slave cert? 
    extensions.append(crypto.X509Extension('subjectKeyIdentifier' , False , 'hash'))
    extensions.append(crypto.X509Extension('authorityKeyIdentifier' , False, 'keyid:always,issuer:always'))
    
    cert.add_extensions(extensions)
    cert.sign(cakey, 'sha1')
    
    return cert

def check_cert_key_match(cert, key):
    """
    Confirm that specified certificate and key are a "pair".
    :param cert: The :class:`OpenSSL.crypto.X509` object or certificate in PEM format.
    :param key: The :class:`OpenSSL.crypto.PKey` object or private key in PEM format.
    :return: `True` if the cert and key match; False otherwise. 
    """
    if not isinstance(cert, crypto.X509Type):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    if not isinstance(key, crypto.PKeyType):
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)

    context = SSL.Context(SSL.SSLv3_METHOD)
    try:
        context.use_certificate(cert)
        context.use_privatekey(key)
        return True
    except:
        return False


def dump_to_file(material, destpath, mode=0644, format=crypto.FILETYPE_PEM):
    """
    Writes the passed-in key/req/cert to file.
    
    :param material: A :class:`OpenSSL.crypto.X509`, :class:`OpenSSL.crypto.PKey` or :class:`OpenSSL.crypto.X509Req` object.
    :param destpath: The path to the file that should be created.
    :param mode: The mode with which to create the file.
    :param format: The format for the file (PEM or DER).
    """
    dump_func = None
    if isinstance(material, crypto.X509):
        dump_func = crypto.dump_certificate
    elif isinstance(material, crypto.PKey):
        dump_func = crypto.dump_privatekey
    elif isinstance(material, crypto.X509Req):
        dump_func = crypto.dump_certificate_request
    else:
        # FIXME: Exception type
        raise Exception("Don't know how to dump content type to file: %s (%r)" % (type(material), material))
    
    content = dump_func(format, material)
    
    destfd = os.open(destpath, os.O_RDWR|os.O_CREAT, mode)
    try:
        os.write(destfd, content)
    finally:
        os.close(destfd)

def load_from_file(materialfile, objtype, format=crypto.FILETYPE_PEM):
    """
    Loads the file into the appropriate openssl object type.
    
    :param materialfile: The file path that holds the key/req/cert
    :param objtype: The type to load -- use the OpenSSL.crypto classes, i.e. crypto.PKey, crypto.X509, crypto.X509Req 
    :param format: The format of the file (crypto.FILETYPE_PEM or crypto.FILETYPE_DER)
    :return The OpenSSL.crypto object type that corresponds to the input (and objtype param).
    :rtype :class:`OpenSSL.crypto.X509` or :class:`OpenSSL.crypto.PKey` or :class:`OpenSSL.crypto.X509Req` 
    """
    if objtype is crypto.X509:
        load_func = crypto.load_certificate
    elif objtype is crypto.X509Req:
        load_func = crypto.load_certificate_request
    elif objtype is crypto.PKey:
        load_func = crypto.load_privatekey
    else:
        raise Exception("Unsupported material type: %s" % (objtype,))
    
    with open(materialfile, 'r') as fp:
        buf = fp.read()
        
    material = load_func(format, buf)
    return material

def retrieve_key_from_file(keyfile):
    return load_from_file(keyfile, crypto.PKey)

def retrieve_csr_from_file(csrfile):
    return load_from_file(csrfile, crypto.X509Req)

def retrieve_cert_from_file(certfile):
    return load_from_file(certfile, crypto.X509)