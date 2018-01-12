#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a skeleton file that can serve as a starting point for a Python
console script. To run this script uncomment the following line in the
entry_points section in setup.cfg:

    console_scripts =
     fibonacci = whoisd_rwhois.skeleton:run

Then run `python setup.py install` which will install the command `fibonacci`
inside your current environment.
Besides console scripts, the header (i.e. until _logger...) of this file can
also be used as template for Python modules.

Note: This skeleton file can be safely removed if not needed!
"""
from __future__ import division, print_function, absolute_import

import argparse
import sys
import logging
import socket
import threading
import socketserver
from whoisd_rwhois import __version__
from simple_rest_client.api import API
from simple_rest_client.resource import Resource

__author__ = "Georg Kahest"
__copyright__ = "Georg Kahest"
__license__ = "mit"

_logger = logging.getLogger(__name__)
_count = 0


class WhoisResource(Resource):
   actions = {
        'whois': {'method': 'GET', 'url': '{}.json'}

   }

class MetricData():
    finish = 0

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):


    def handle(self):

        # take data in as byte input
        data = self.request.recv(1024).strip()

        # convert input to utf-8 string
        data_str = str(data, 'utf-8')
        cur_thread = threading.current_thread()
        _logger.debug("thread: ")
        _logger.debug(cur_thread)



        # restful-whois
        default_params = {'access_token': 'valid-token'}
        rwhois_api = API(
            api_root_url='https://rwhois.internet.ee/v1/', params=default_params,
            json_encode_body=True
        )
        rwhois_api.add_resource(resource_name='domain', resource_class=WhoisResource)
        rwhois_response = rwhois_api.domain.whois(data_str, body=None, params={}, headers={})
        # try:
        #    rwhois_response = rwhois_api.domain.whois(data_str, body=None, params={}, headers={})
        # except Exception as e:
        #    z = e  # representation: "<exceptions.ZeroDivisionError instance at 0x817426c>"
        #    _logger.debug(z)  # output: "integer division or modulo by zero"

        sisu = rwhois_response.body

        # TODO: implement discolese  in rwhois json?
        sisu['disclose'] = "Not Disclosed - Visit www.internet.ee for webbased WHOIS"

        response = bytes("{}: {} {}\n".format(cur_thread.name, data_str, MetricData.finish), 'utf-8')
        response += bytes("Estonia .ee Top Level Domain WHOIS server \n \nDomain: \n", 'utf-8')
        response += bytes("{:<12}{}\n".format('name:',sisu['name']), 'utf-8')

        # handle multiple status entries
        for x in sisu['status']:
            response += bytes("{:<12}{}\n".format('status:',x), 'utf-8')

        response += bytes("{:<12}{}\n".format('registered:',sisu['registered'].replace("T", " ").replace("+", " +")), 'utf-8')
        response += bytes("{:<12}{}\n".format('changed:',sisu['changed'].replace("T", " ").replace("+", " +")), 'utf-8')
        response += bytes("{:<12}{}\n".format('expire:',sisu['expire']), 'utf-8')
        response += bytes("{:<12}{}\n".format('outzone:',str(sisu['outzone'] or '')), 'utf-8')
        response += bytes("{:<12}{}\n\n".format('delete:',str(sisu['delete'] or '')), 'utf-8')

        # Registrant
        response += bytes("{}\n{:<12}{}\n".format('Registrant:','name:',sisu['registrant']), 'utf-8')
        if sisu['registrant_kind'] == "org":
           response += bytes("{:<12}{}\n".format('org id:',sisu['registrant_reg_no']), 'utf-8')
           response += bytes("{:<12}{}\n".format('country:', sisu['registrant_ident_country_code']), 'utf-8')
        response += bytes("{:<12}{}\n".format('email:', sisu['disclose']), 'utf-8')
        response += bytes("{:<12}{}\n".format('changed:', sisu['registrant_changed'].replace("T", " ").replace("+", " +")), 'utf-8')

        # Administrative contacts
        response += bytes("\n{}\n".format('Administrative contact:'), 'utf-8')
        for x in sisu['admin_contacts']:
            response += bytes("{:<12}{}\n".format('name:',x['name']), 'utf-8')
            response += bytes("{:<12}{}\n".format('email:', sisu['disclose']), 'utf-8')
            response += bytes("{:<12}{}\n".format('changed:', x['changed'].replace("T", " ").replace("+", " +")), 'utf-8')

        # Tech contacs
        response += bytes("\n{}\n".format('Technical contact:'), 'utf-8')
        for x in sisu['tech_contacts']:
            response += bytes("{:<12}{}\n".format('name:',x['name']), 'utf-8')
            response += bytes("{:<12}{}\n".format('email:', sisu['disclose']), 'utf-8')
            response += bytes("{:<12}{}\n".format('changed:', x['changed'].replace("T", " ").replace("+", " +")), 'utf-8')

        # Registrar
        response += bytes("\n{}\n".format('Registrar:'), 'utf-8')
        response += bytes("{:<12}{}\n".format('name:', sisu['registrar']), 'utf-8')
        response += bytes("{:<12}{}\n".format('url:', sisu['registrar_website']), 'utf-8')
        response += bytes("{:<12}{}\n".format('phone:', sisu['registrar_phone']), 'utf-8')
        response += bytes("{:<12}{}\n".format('changed:', sisu['registrar_changed'].replace("T", " ").replace("+", " +")), 'utf-8')

        # Name servers
        response += bytes("\n{}\n".format('Name servers:'), 'utf-8')
        for x in sisu['nameservers']:
            response += bytes("{:<12}{}\n".format('nserver:',x), 'utf-8')
        response += bytes("{:<12}{}\n".format('changed:', sisu['nameservers_changed'].replace("T", " ").replace("+", " +")), 'utf-8')

        # DNSSec Keys
        if sisu['dnssec_keys'] != []:
            response += bytes("\n{}\n".format('DNNSEC:'), 'utf-8')
            for x in sisu['dnssec_keys']:
                    response += bytes("{:<12}{}\n".format('dnskey:',x), 'utf-8')
            response += bytes("{:<12}{}\n".format('changed:', sisu['dnssec_changed'].replace("T", " ").replace("+", " +")), 'utf-8')

        # Footer
        response += bytes("\nEstonia .ee Top Level Domain WHOIS server\nMore information at https://internet.ee", 'utf-8')

        # Send response
        self.request.sendall(response)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address,
                 handler_class=ThreadedTCPRequestHandler,
                 ):
        self.logger = logging.getLogger('ThreadedTCPServer')
        self.logger.debug('__init__')
        socketserver.TCPServer.__init__(self, server_address,
                                        handler_class)
        return

    def server_activate(self):
        self.logger.debug('server_activate')
        socketserver.TCPServer.server_activate(self)
        return

    def serve_forever(self, poll_interval=0.5):
        self.logger.debug('waiting for request')
        self.logger.info(
            'Handling requests, press <Ctrl-C> to quit'
        )
        socketserver.TCPServer.serve_forever(self, poll_interval)
        return

    def handle_request(self):
        self.logger.debug('handle_request')
        return socketserver.TCPServer.handle_request(self)

    def verify_request(self, request, client_address):
        self.logger.debug('verify_request(%s, %s)',
                          request, client_address)
        return socketserver.TCPServer.verify_request(
            self, request, client_address,
        )

    def process_request(self, request, client_address):
        self.logger.debug('process_request(%s, %s)',
                          request, client_address)

        return socketserver.TCPServer.process_request(
            self, request, client_address,
        )

    def server_close(self):
        self.logger.debug('server_close')
        return socketserver.TCPServer.server_close(self)

    def finish_request(self, request, client_address):
        self.logger.debug('finish_request(%s, %s)',
                          request, client_address)
        MetricData.finish+=1
        self.logger.debug(MetricData.finish)
        return socketserver.TCPServer.finish_request(
            self, request, client_address,
        )

    def close_request(self, request_address):
        self.logger.debug('close_request(%s)', request_address)
        return socketserver.TCPServer.close_request(
            self, request_address,
        )

    def shutdown(self):
        self.logger.debug('shutdown()')
        return socketserver.TCPServer.shutdown(self)


def client(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        sock.sendall(bytes(message, 'ascii'))
        response = str(sock.recv(1024), 'ascii')
        print("Received: {}".format(response))
    finally:
        sock.close()


def fib(n):
    """Fibonacci example function

    Args:
      n (int): integer

    Returns:
      int: n-th Fibonacci number
    """
    assert n > 0
    a, b = 1, 1
    for i in range(n-1):
        a, b = b, a+b
    return a


def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="Just a Fibonnaci demonstration")
    parser.add_argument(
        '--version',
        action='version',
        version='whoisd-rwhois {ver}'.format(ver=__version__))
    parser.add_argument(
        dest="n",
        help="n-th Fibonacci number",
        type=int,
        metavar="INT")
    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO)
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(level=loglevel, stream=sys.stdout,
                        format=logformat, datefmt="%Y-%m-%d %H:%M:%S")


def main(args):
    """Main entry point allowing external calls

    Args:
      args ([str]): command line parameter list
    """
    args = parse_args(args)
    setup_logging(args.loglevel)
    _logger.debug("Starting crazy calculations...")
    print("The {}-th Fibonacci number is {}".format(args.n, fib(args.n)))
    HOST, PORT = "localhost", 9999

    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    ip, port = server.server_address

    # Start a thread with the server -- that thread will then start one
    # more thread for each request
    server_thread = threading.Thread(target=server.serve_forever)
    # Exit the server thread when the main thread terminates
    server_thread.daemon = True
    server_thread.start()
    print("Server loop running in thread:", server_thread.name)

    # client(ip, port, "Hello World 1")
    # client(ip, port, "Hello World 2")
    # client(ip, port, "Hello World 3")

    # start server
    server.serve_forever()
    # rerver.server_activate()


    _logger.info("Script ends here")


def run():
    """Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
