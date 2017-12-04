import argparse
import urllib2
import ssl
import sys
from retry import retry

OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

parser = argparse.ArgumentParser(description='ha_proxy utility')
parser.add_argument("-u", "--url", dest="url", help="Statistics URL to check (eg. http://demo.1wt.eu/)")
parser.add_argument("-p", "--proxies [PROXIES]", dest="proxies", help="Only check these proxies (eg. proxy1,proxy2,proxylive)",
                    default=None, required=False)
parser.add_argument("-U", "--user [USER]", dest="user", help="Basic auth user to login as", default=None, required=False)
parser.add_argument("-P", "--password [PASSWORD]", dest="password", help="Basic auth password", default=None, required=False)
parser.add_argument("-w", "--warning [WARNING]", type=int, dest="warning", help="Pct of active sessions (eg 85, 90)", default=1,
                    required=False)
parser.add_argument("-c", "--critical [CRITICAL]", type=int, dest="critical", help="Pct of active sessions (eg 90, 95)", default=2,
                    required=False)
parser.add_argument('-k', '--insecure', dest="insecure", help='Allow insecure TLS/SSL connections', default=True,
                    required=False)
parser.add_argument('-r', '--redirect', dest="redirect", help='Depth of redirect to follow', default=2,
                    required=False)
parser.add_argument('--http-error-critical', dest="http_error_critical",
                    help='Throw critical when connection to HAProxy is refused or returns error code',
                    default=False, required=False)

args = parser.parse_args()
class RedirectionException(Exception):
    pass


class HaProxy:
    def __init__(self, args):
        self.args = args
        self.request_context = None
        self._checkRules()
        self._getInfo()

    def _checkRules(self):
        if not (0 <= self.args.warning <= 100) :
            raise Exception("warning should be between [0-100]")

        if not (0 <= self.args.critical <= 100) :
            raise Exception("critical should be between [0-100]")

        if self.args.warning > self.args.critical :
            raise Exception('ERROR: warning must be below critical')

        if (self.args.user and not self.args.password) or (self.args.password and not self.args.user) :
            raise Exception("User cannot exist without password and viceversa ")

        if "http" not in self.args.url :
            raise Exception("protocol is missing from url")

    def _getInfo(self):
        if ";" not in self.args.url:
            self.args.url = self.args.url + "/;csv"

        if self.args.proxies:
            self.args.proxies = self.args.proxies.split(",")

        if self.args.user :
            self._install_basic_auth()

        if self.args.insecure and "https" in self.args.url:
            self.request_context = ssl._create_unverified_context()


    def _install_basic_auth(self):
        auth_handler = urllib2.HTTPBasicAuthHandler()
        auth_handler.add_password(realm=None, host=self.args.url, user=self.args.user,
                                  passwd=self.args.password)
        opener = urllib2.build_opener(auth_handler)
        urllib2.install_opener(opener)

    def call(self):
        try:
            self.makeRequest()
        except RedirectionException:
            print ("to many redirects, max 2 allowed")
            sys.exit(status=UNKNOWN)

    @retry(RedirectionException, tries=args.redirect, delay=3, backoff=2)
    def makeRequest(self):
        try:
            response = urllib2.urlopen(self.args.url, context=self.request_context)
            if response.code == 302:
                self.args.url = response.geturl()
                raise RedirectionException("make redirect")
            data = response.read().strip()
            self.validateResponse(data)
        except urllib2.HTTPError, e:
            print e.code, e.message
            if self.args.http_error_critical:
                sys.exit(status=CRITICAL)
            else:
                sys.exit(status=UNKNOWN)
        except urllib2.URLError, e:
            # connection refused
            print e.message
            if self.args.http_error_critical:
                sys.exit(status=CRITICAL)
            else:
                sys.exit(status=UNKNOWN)

    def validate_response(self, data):
        lines = data.splitlines()
        for line in lines:





