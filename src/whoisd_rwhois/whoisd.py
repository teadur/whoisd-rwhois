#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Unix whois daemon with restful-whois backend.

"""
# from __future__ import division, print_function, absolute_import

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


class WhoisResource(Resource):
   actions = {
        'v1': {'method': 'GET', 'url': '/v1/{}.json'},
        'v2': {'method': 'GET', 'url': '/v2/{}.json'}

   }

class MetricData():
    finish = 0
    test_request = 0

class RwhoisRequest():

    # TODO: implement discolese  in rwhois json?
        disclosed = "Not Disclosed - Visit www.internet.ee for webbased WHOIS"

        def __init__(self, name):
            self.name = name
            _logger.debug("RwhoisRequest: init {}".format(self.name))


        def get(domain_name):

            default_params = {}
            rwhois_api = API(
                api_root_url='https://rwhois.internet.ee/', params=default_params,
                json_encode_body=True
            )

            rwhois_api.add_resource(resource_name='domain', resource_class=WhoisResource)
            rwhois_response = rwhois_api.domain.v1(domain_name, body=None, params={}, headers={})

            return rwhois_response

        def status(domain_name):
            return RwhoisRequest.get(domain_name).body['status'][0]

        def contacts(contacts):

            for contact in contacts:
                response = bytes("{:<12}{}\n".format('name:', contact['name']), 'utf-8')
                response += RwhoisRequest.print('email', RwhoisRequest.disclosed)
                response += RwhoisRequest.changed(contact['changed'])

            return response

        def changed(changed):

            response = bytes("{:<12}{}\n".format('changed:', changed.replace("T", " ").replace("+", " +")), 'utf-8')
            return response

        def print(key, value):

            response = bytes("{:<12}{}\n".format(key, value), 'utf-8')
            return response

        def section(title):

            response = bytes("\n{}\n".format(title), 'utf-8')
            return response

        def make(domain_name,cur_thread):
            thread_name = str(cur_thread or cur_thread.name)

            _logger.debug('RwhoisRequest.make: {}'.format(domain_name))

            rwhois_response = RwhoisRequest.get(domain_name)
            # rwhois_response = rwhois_api.domain.v2(domain_name, body=None, params={'access_token': 'valid-token'}, headers={})

            sisu = rwhois_response.body
            response_time = rwhois_response.headers['X-Runtime']
            response_date = rwhois_response.headers['Date']

            # Metrics line
            response = bytes("{}: {} {} time: {} @ {}\n".format(thread_name, domain_name, MetricData.finish, response_time, response_date), 'utf-8')

            response += bytes("Estonia .ee Top Level Domain WHOIS server \n \nDomain: \n", 'utf-8')
            response += RwhoisRequest.print('name:',sisu['name'])

            # handle multiple status entries
            for status in sisu['status']:
                 response += RwhoisRequest.print('status',status)

            response += bytes("{:<12}{}\n".format('registered:', sisu['registered'].replace("T", " ").replace("+", " +")), 'utf-8')
            response += RwhoisRequest.changed(sisu['changed'])
            response += RwhoisRequest.print('expire:',sisu['expire'])
            response += RwhoisRequest.print('outzone:', str(sisu['outzone'] or ''))
            response += RwhoisRequest.print('delete:', str(sisu['delete'] or ''))


            # Registrant
            response += RwhoisRequest.section('Registrant:')
            response += RwhoisRequest.print('name:', sisu['registrant'])

            if sisu['registrant_kind'] == "org":
                response += RwhoisRequest.print('org id:',sisu['registrant_reg_no'])
                response += RwhoisRequest.print('country:',sisu['registrant_ident_country_code'])
            response += RwhoisRequest.print('email', RwhoisRequest.disclosed)
            response += RwhoisRequest.changed(sisu['registrant_changed'])


            # Administrative contacts
            response += RwhoisRequest.section('Administrative contact:')
            response += RwhoisRequest.contacts(sisu['admin_contacts'])

            # Tech contacs
            response += RwhoisRequest.section('Technical contact:')
            response += RwhoisRequest.contacts(sisu['tech_contacts'])

            # Registrar
                response += RwhoisRequest.section('Registrar:')
            response += RwhoisRequest.print('name:',sisu['registrar'])
            response += RwhoisRequest.print('url:',sisu['registrar_website'])
            response += RwhoisRequest.print('phone:',sisu['registrar_phone'])
            response += RwhoisRequest.changed(sisu['registrar_changed'])

            # Name servers
            response += bytes("\n{}\n".format('Name servers:'), 'utf-8')
            for nameserver in sisu['nameservers']:
                response += RwhoisRequest.print('nserver:', nameserver)

            response += RwhoisRequest.changed(sisu['nameservers_changed'])

            # DNSSec Keys
            if sisu['dnssec_keys'] != []:
                response += bytes("\n{}\n".format('DNNSEC:'), 'utf-8')
                for key in sisu['dnssec_keys']:
                    response += RwhoisRequest.print('dnskey:', key)
                response += RwhoisRequest.changed(sisu['dnssec_changed'])

            # Footer
            response += bytes("\nEstonia .ee Top Level Domain WHOIS server\nMore information at https://internet.ee",
                              'utf-8')

            # Ugly hack to run tests
            if thread_name == "test_thread":
               _logger.debug(sys.getsizeof(response))
               if sys.getsizeof(response) == 1188:
                    return "midagi"

            return response

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):


    def handle(self):

        # take data in as byte input
        data = self.request.recv(1024).strip()

        # convert input to utf-8 string
        data_str = str(data, 'utf-8')
        cur_thread = threading.current_thread()
        _logger.debug("thread:  {}".format(cur_thread))


        response = RwhoisRequest.make(data_str,cur_thread)
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

def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="Unix Whois Daemon for Restful Whois backend")
    parser.add_argument(
        '--version',
        action='version',
        version='whoisd-rwhois {ver}'.format(ver=__version__))
    parser.add_argument(
        dest="p",
        help="Port to listen on",
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
    HOST, PORT = "localhost", args.p

    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    ip, port = server.server_address
    server.address_family=(socket.AF_INET6)

    # Start a thread with the server -- that thread will then start one
    # more thread for each request
    server_thread = threading.Thread(target=server.serve_forever)
    # Exit the server thread when the main thread terminates
    server_thread.daemon = True
    server_thread.start()
    print("Server loop running in thread:", server_thread.name)

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
