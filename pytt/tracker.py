#!/usr/bin/env python
#
# BitTorrent Tracker using Tornado
#
# @author: Sreejith K <sreejithemk@gmail.com>
# Created on 12th May 2011
# http://foobarnbaz.com


import sys
import logging
import tornado.ioloop
import tornado.web
import tornado.httpserver
from optparse import OptionParser
from bencode import bencode
import utils
from utils import BaseHandler, no_of_leechers, no_of_seeders


class TrackerStats(BaseHandler):
    """Shows the Tracker statistics on this page.
    """
    def get(self):
        self.send_error(404)


global_info_hash = None


class AnnounceHandler(BaseHandler):
    """Track the torrents. Respond with the peer-list.
    """

    def decode_argument(self, value, name=None):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value

    def get(self):
        global global_info_hash
        failure_reason = ''
        warning_message = ''

        # get all the required parameters from the HTTP request.
        info_hash = self.get_argument('info_hash')
        if info_hash:
            global_info_hash = info_hash
        peer_id = self.get_argument('peer_id')
        try:
            ip = self.get_argument('remote_ip')
        except:
            ip = self.request.remote_ip
        if not ip:
            ip = self.request.remote_ip

        port = self.get_argument('port')

        # send appropirate error code.
        if not info_hash:
            return self.send_error(utils.MISSING_INFO_HASH)

        if not peer_id:
            return self.send_error(utils.MISSING_PEER_ID)

        if not port:
            return self.send_error(utils.MISSING_PORT)

        # if len(info_hash) != utils.INFO_HASH_LEN:
        #    return self.send_error(utils.INVALID_INFO_HASH)
        # if len(peer_id) != utils.PEER_ID_LEN:
        #    return self.send_error(utils.INVALID_PEER_ID)

        # get the optional parameters.
        # uploaded = int(self.get_argument('uploaded', 0))
        # downloaded = int(self.get_argument('downloaded', 0))
        # left = int(self.get_argument('left', 0))
        compact = int(self.get_argument('compact', 0))
        # no_peer_id = int(self.get_argument('no_peer_id', 0))
        event = self.get_argument('event', '')
        numwant = int(self.get_argument('numwant',
                                        utils.DEFAULT_ALLOWED_PEERS))

        if numwant > utils.MAX_ALLOWED_PEERS:
            # cannot request more than MAX_ALLOWED_PEERS.
            self.send_error(utils.INVALID_NUMWANT)

        # FIXME: What to do with these parameters?
        # key = self.get_argument('key', '')
        tracker_id = self.get_argument('trackerid', '')

        # store the peer info
        if event:
            print "[+] storing peer %s" % ip
            utils.store_peer_info(info_hash, peer_id, ip, port, event)

        # generate response
        response = {}
        # Interval in seconds that the client should wait between sending
        #    regular requests to the tracker.
        response['interval'] = utils.get_config().getint('tracker', 'interval')
        # Minimum announce interval. If present clients must not re-announce
        #    more frequently than this.
        response['min interval'] = utils.get_config().getint('tracker',
                                                             'min_interval')
        # FIXME
        response['tracker id'] = tracker_id
        response['complete'] = utils.no_of_seeders(info_hash)
        response['incomplete'] = utils.no_of_leechers(info_hash)

        # get the peer list for this announce
        response['peers'] = utils.get_peer_list(info_hash, numwant, compact,
                                                True)

        # set error and warning messages for the client if any.
        if failure_reason:
            response['failure reason'] = failure_reason
        if warning_message:
            response['warning message'] = warning_message

        # send the bencoded response as text/plain document.
        self.set_header('content-type', 'text/plain')
        print "<<<", response
        self.write(bencode(response))


class FakeAnnounceHandler(BaseHandler):
    """Track the torrents. Respond with the peer-list.
    """

    def decode_argument(self, value, name=None):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value

    def get(self):
        info_hash = global_info_hash
        peer_id = "XXX"
        ip = self.get_argument('remote_ip')
        port = self.get_argument('remote_port')

        if not ip or not port:
            self.write("FFF")
            return

        # store the peer info
        print "[+] storing FAKE peer %s:%s" % (ip, port)
        utils.store_peer_info(info_hash, peer_id, ip, port, 1)

        self.set_header('content-type', 'text/plain')
        self.write("OK")


class ScrapeHandler(BaseHandler):
    """Returns the state of all torrents this tracker is managing.
    """

    def decode_argument(self, value, name=None):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value

    def get(self):
        info_hashes = self.get_arguments('info_hash')
        response = {}
        for info_hash in info_hashes:
            info_hash = str(info_hash)
            response[info_hash] = {}
            response[info_hash]['complete'] = no_of_seeders(info_hash)
            # FIXME: number of times clients have registered completion.
            response[info_hash]['downloaded'] = no_of_seeders(info_hash)
            response[info_hash]['incomplete'] = no_of_leechers(info_hash)
            response[info_hash]['name'] = "XXX"
            # response[info_hash]['name'] = bdecode(info_hash).get(name, '')

        # send the bencoded response as text/plain document.
        self.set_header('content-type', 'text/plain')
        self.write(bencode(response))


def run_app(port):
    """Start Tornado IOLoop for this application.
    """
    tracker = tornado.web.Application([
        (r"/announce.*", AnnounceHandler),
        (r"/fake.*", FakeAnnounceHandler),
        (r"/scrape.*", ScrapeHandler),
        (r"/", TrackerStats),
    ])
    logging.info('Starting Pytt on port %d' % port)
    http_server = tornado.httpserver.HTTPServer(tracker)
    http_server.listen(port)
    tornado.ioloop.IOLoop.instance().start()


def start_tracker():
    """Start the Torrent Tracker.
    """
    # parse commandline options
    parser = OptionParser()
    parser.add_option('-p', '--port', help='Tracker Port', default=0)
    parser.add_option('-b', '--background', action='store_true', default=False,
                      help='Start in background')
    parser.add_option('-d', '--debug', action='store_true', default=False,
                      help='Debug mode')
    (options, args) = parser.parse_args()

    # setup directories
    utils.create_pytt_dirs()
    # setup logging
    utils.setup_logging(options.debug)

    try:
        # start the torrent tracker
        run_app(int(options.port) or utils.get_config().getint('tracker',
                                                               'port'))
    except KeyboardInterrupt:
        logging.info('Tracker Stopped.')
        utils.close_db()
        sys.exit(0)
    except Exception, ex:
        logging.fatal('%s' % str(ex))
        utils.close_db()
        sys.exit(-1)


if __name__ == '__main__':
    start_tracker()
