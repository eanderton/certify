import sys
import optparse
import logging

from certify import __version__, config, server, utils

if __name__ == "__main__":
    
    usage = 'certmaster [OPTIONS]'
    parser = optparse.OptionParser(usage=usage, version='%prog ' +  __version__)
    
    parser.add_option('-c', '--config=', dest="config", default="/etc/certmaster/certmaster.conf", action="store",
          help='The configuration file to use.')
    
    parser.add_option('-d', '--daemon', default=False, action="store_true",
          help='Run in background (as a daemon).')
    
    parser.add_option('-q', '--quiet', default=False, action="store_true",
          help='No console logging (only relevant if not running as daemon)')
    
    parser.add_option('--log-requests', dest="log_requests", default=False, action="store_true",
                      help='Whether to log the XML-RPC requests.')
    
    parser.add_option('--verbose', default=False, action="store_true",
          help='Console debug logging (only relevant if not running as daemon)')
          
    (opts, args) = parser.parse_args()
    
    add_console = ((not opts.quiet) and (not opts.daemon))
    if add_console:
        if opts.verbose:
            console_level = logging.DEBUG
        else:
            console_level = logging.INFO
    else:
        console_level = None
        
    
    config.init_logging(opts.config, console_level=console_level)
    config.init_certmaster_config(opts.config)
    
    log = logging.getLogger(__name__)
    
    server = server.CertMaster()
    
    if opts.daemon:
        utils.daemonize(config.certmaster_config.pid_file)
    
    try:
        server.serve(server, log_requests=opts.log_requests)
    except KeyboardInterrupt:
        log.debug("shutting down due to user input")
        sys.exit(0)
    except:
        log.exception("unexpected error")
        sys.exit(1)
    