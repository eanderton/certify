#!/usr/bin/python -tt
# sign/list keys
# --sign hostname hostname hostname
# --list # lists all csrs needing to be signed
# --list-all ?
# --clean? not sure what it will do

import sys
import glob
import optparse
import os

from certify import config, server, utils

def errorprint(stuff):
    print >> sys.stderr, stuff

def main():
    usage = 'certify-ca <option> [args]'
    parser = optparse.OptionParser(
        usage=usage,
        version='%prog - ' + utils.get_version_str())
   
    parser.add_option('-l', '--list', default=False, action="store_true",
          help='list signing requests remaining')
    parser.add_option('-s', '--sign', default=False, action="store_true",
          help='sign requests of hosts specified')
    parser.add_option('-c', '--clean', default=False, action="store_true",
          help="clean out all certs or csrs for the hosts specified")
    parser.add_option("", "--list-signed", default=False, action="store_true",
          help='list all signed certs')
    parser.add_option("", "--list-cert-hash", default=False, action="store_true",
          help="list the cert hash for signed certs")
          
    (opts, args) = parser.parse_args()
    
    # gotta be a better way...
    if not opts.list and not opts.sign and not opts.clean \
            and not opts.list_signed and not opts.list_cert_hash:
        parser.print_help()
        sys.exit(1)
            
    if os.geteuid() != 0:
        errorprint('Must be root to run certify-ca')
        return 1

    configuration = config.CMConfig()
    cm = server.CertMaster(configuration)
        
    if opts.list:
        hns = cm.get_csrs_waiting()
        if hns:
            for hn in sorted(hns):
                print hn
        else:
           print 'No certificates to sign'

        return 0
    
    if opts.sign:
        if not args:
            errorprint('Need hostnames to sign')
            return 1
            
        for hn in args:
            csrglob = '%s/%s.csr' % (cm.cfg.csrroot, hn)
            csrs = glob.glob(csrglob)
            if not csrs:
                errorprint('No match for %s to sign' % hn)
                return 1
            
            for fn in csrs:
                certfile = cm.sign_this_csr(fn)
                print '%s signed - cert located at %s' % (fn, certfile)
        return 0
    
    if opts.clean:
        if not args:
            errorprint('Need hostname(s) to clean up')
            return 1
        
        for hn in args:
            cm.remove_this_cert(hn)
        
        return 0

    if opts.list_signed:
        hostglobs = ["*"]
        if args:
            hostglobs = args

        signed_certs = cm.get_signed_certs(args)

        for i in sorted(signed_certs):
            print i
            
        return 0
        
    if opts.list_cert_hash:
        hostglobs = ["*"]
        if args:
            hostglobs = args
            
        cert_hashes = cm.get_cert_hashes(hostglobs)

        for i in sorted(cert_hashes):
            print i
            
        return 0
