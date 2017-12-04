# haproxyPy
easy haproxy checker in python

usage:

```
python ha_proxy.py -u "https://google.com/stats" -U <some_user> -P <some_passwd> -r 3 -w 1 -c 2 --insecure
```

docs:

```
ha_proxy utility

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Statistics URL to check (eg. http://demo.1wt.eu/)
  -p PROXIES, --proxies [PROXIES] PROXIES
                        Only check these proxies (eg. proxy1,proxy2,proxylive)
  -U USER, --user [USER] USER
                        Basic auth user to login as
  -P PASSWORD, --password [PASSWORD] PASSWORD
                        Basic auth password
  -w WARNING, --warning [WARNING] WARNING
                        Pct of active sessions (eg 85, 90)
  -c CRITICAL, --critical [CRITICAL] CRITICAL
                        Pct of active sessions (eg 90, 95)
  -k [INSECURE], --insecure [INSECURE]
                        Allow insecure TLS/SSL connections
  -r REDIRECT, --redirect REDIRECT
                        Depth of redirect to follow
  --http-error-critical [HTTP_ERROR_CRITICAL]
                        Throw critical when connection to HAProxy is refused
                        or returns error code
```