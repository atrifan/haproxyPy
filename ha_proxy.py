import argparse
import urllib2
import ssl
import sys
import csv
import base64

OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3
status = ['OK', 'WARN', 'CRIT', 'UNKN']


parser = argparse.ArgumentParser(description='ha_proxy utility')
parser.add_argument("-u", "--url", dest="url", help="Statistics URL to check (eg. http://demo.1wt.eu/)")
parser.add_argument("-p", "--proxies [PROXIES]", dest="proxies", help="Only check these proxies (eg. proxy1,proxy2,proxylive)",
                    default='', required=False)
parser.add_argument("-U", "--user [USER]", dest="user", help="Basic auth user to login as", default=None, required=False)
parser.add_argument("-P", "--password [PASSWORD]", dest="password", help="Basic auth password", default=None, required=False)
parser.add_argument("-w", "--warning [WARNING]", type=int, dest="warning", help="Pct of active sessions (eg 85, 90)", default=-1,
                    required=False)
parser.add_argument("-c", "--critical [CRITICAL]", type=int, dest="critical", help="Pct of active sessions (eg 90, 95)", default=-1,
                    required=False)
parser.add_argument('-k', '--insecure', dest="insecure", help='Allow insecure TLS/SSL connections', default=True,
                    required=False, nargs='?', const=True)
parser.add_argument('-r', '--redirect', dest="redirect", help='Depth of redirect to follow', default=2,
                    required=False, type=int)
parser.add_argument('--http-error-critical', dest="http_error_critical", nargs='?', const=True,
                    help='Throw critical when connection to HAProxy is refused or returns error code',
                    default=False, required=False)

class RedirectionException(Exception):
    pass

class HaProxy:
    def __init__(self):
        self.args = parser.parse_args()
        self.request_context = None
        self.perfdata = []
        self.errors = []
        self.proxies = []
        self.exit_code = OK
        self._checkRules()
        self._getInfo()

    def _checkRules(self):
        if not (0 <= self.args.warning <= 100) and self.args.warning != -1:
            raise Exception("warning should be between [0-100]")

        if not (0 <= self.args.critical <= 100) and self.args.critical != -1:
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
        else:
            self.args.proxies = []

        if self.args.insecure and "https" in self.args.url:
            self.request_context = ssl._create_unverified_context()

    def call(self):
        try:
            self.makeRequest()
        except RedirectionException:
            print ("to many redirects, max 2 allowed")
            sys.exit(UNKNOWN)

    def makeRequest(self):
        request = urllib2.Request(self.args.url)
        if self.args.user:
            base64string = base64.encodestring('{}:{}'.format(self.args.user, self.args.password)).replace('\n', '')
            request.add_header("Authorization", "Basic {}".format(base64string))

        try:
            response = urllib2.urlopen(request, context=self.request_context)
            if response.code == 302:
                if self.args.redirect > 0:
                    self.args.url = response.geturl()
                    self.args.redirect = self.args.redirect - 1
                    self.makeRequest()
                else:
                    print "maximum redirects depth reached"
                    sys.exit(UNKNOWN)
            data = response.read().strip()
            self.validate_response(data)
        except urllib2.HTTPError, e:
            print e.code, e
            if self.args.http_error_critical:
                sys.exit(CRITICAL)
            else:
                sys.exit(UNKNOWN)
        except urllib2.URLError, e:
            # connection refused
            print e
            if self.args.http_error_critical:
                sys.exit(CRITICAL)
            else:
                sys.exit(UNKNOWN)

    def validate_response(self, data):
        lines = data.splitlines()
        if lines[0].startswith('#'):
            lines[0] = lines[0][2:-1]
        else:
            print("ERROR: CSV header is missing")
            sys.exit(UNKNOWN)

        table = csv.DictReader(lines, delimiter=',')
        for row in table:

            self._cast_ints(row)

            if not (len(self.args.proxies) == 0 or row['pxname'] in self.args.proxies):
                continue

            if row['pxname'] in ['statistics', 'admin_stats', 'stats']:
                continue

            if int(row['act']) > 0:
                role = 'active'
            elif int(row['bck'] > 0):
                role = 'backup'
            else:
                role = ''
            message = '{}: {} {}{}'.format(row['pxname'], row['status'], role, row['svname'])
            perf_id = row['pxname'].lower()

            if row['svname'] == 'FRONTEND':
                if int(row['slim']) == 0 :
                    session_percent_usage = 0
                else:
                    session_percent_usage = int(row['scur']) * 100 / int(row['slim'])

                warning = "0"
                critical = "0"

                if self.args.warning != -1:
                    warning = self.args.warning

                if self.args.critical != -1:
                    critical = self.args.critical

                self.perfdata.append("{}_sessions={}%;{};{};;".format(perf_id, session_percent_usage, warning, critical))
                self.perfdata.append("{}_rate=;;;;{}".format(perf_id,row['rate'], row['rate_max']))

                if self.args.critical !=-1 and session_percent_usage > self.args.critical:
                    self.errors.append("{} has way too many sessions({}/{}) on {} proxy".format(
                        row['svname'], row['scur'], row['slim'], row['pxname']
                    ))
                    self.exit_code = CRITICAL
                elif self.args.warning != -1 and session_percent_usage > self.args.warning:
                    self.errors.append("{} has too many sessions({}/{}) on {} proxy".format(
                        row['svname'], row['scur'], row['slim'], row['pxname']
                    ))
                    if self.exit_code == OK or self.exit_code == UNKNOWN:
                        self.exit_code = WARNING

                if row['status'] != 'OPEN' and row['status'] != 'UP':
                    self.errors.append(message)
                    self.exit_code = CRITICAL

            elif row['svname'] == 'BACKEND':
                # It has no point to check sessions number for backends, against the alert limits,
                # as the SLIM number is actually coming from the "fullconn" parameter.
                # So we just collect perfdata. See the following url for more info:
                # http://comments.gmane.org/gmane.comp.web.haproxy/9715
                current_sessions = int(row['scur'])
                self.perfdata.append("{}_sessions={};;;;".format(perf_id, current_sessions))
                self.perfdata.append("{}_rate={};;;;{}".format(perf_id, row['rate'], row['rate_max']))
                if row['status'] != 'OPEN' and row['status'] != 'UP':
                    self.errors.append(message)
                    self.exit_code = CRITICAL

            elif row['status'] != 'no check':
                self.proxies.append(message)
                if row['status'] != 'UP':
                    self.errors.append(message)
                    if self.exit_code == OK or self.exit_code == UNKNOWN:
                        self.exit_code = WARNING
                else:
                    if int(row['slim']) == 0:
                        session_percent_usage = 0
                    else:
                        session_percent_usage = int(row['scur']) * 100 / int(row['slim'])

                    self.perfdata.append('{}-{}_sessions={}%;;;;'.format(perf_id, row['svname'], session_percent_usage))
                    self.perfdata.append('{}-{}_rate={};;;;{}'.format(perf_id, row['svname'], row['rate'], row['rate_max']))

        if len(self.errors) == 0:
            self.errors.append("{} proxies found".format(len(self.proxies)))

        if len(self.proxies) == 0:
            self.errors.append("No proxies listed as up or down")
            if self.exit_code == OK:
                self.exit_code = UNKNOWN

        print("HAPROXY {}: {}|{}".format(status[self.exit_code], "; ".join(self.errors), " ".join(self.perfdata)))
        print("{}".format("\n".join(self.proxies)))
        sys.exit(self.exit_code)

    def _cast_ints(self, row):
        if "slim" in row and not row['slim']:
            row['slim'] = '0'

        if "scur" in row and not row['scur']:
            row['scur'] = '0'

        if "bck" in row and not row['bck']:
            row['bkup'] = '0'

        if "act" in row and not row['act']:
            row['act'] = '0'



haProxy = HaProxy()
haProxy.makeRequest()



