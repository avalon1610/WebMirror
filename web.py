# -*- coding: utf-8 -*-
'''
mirror google search
'''
import sys
import os
import re
from urlparse import urlparse
import tornado.web
import requests

CONST_STRING = {
    'explorer': ('走你',),
    'username': ('用户名',),
    'password': ('密码',),
    'login': ('登录',),
    'config': ('配置',)
}

LANGUAGE = 0
DEBUG = False


def log(message):
    '''
     print log if DEBUG flag is on
    '''
    if DEBUG:
        print message


def get_render_param(*args, **kwargs):
    '''
    get render string in pre-defined const string
    '''
    ret = {}
    for arg in args:
        ret[arg] = arg if LANGUAGE == 0 else CONST_STRING[arg][LANGUAGE]
    for k in kwargs:
        ret[k] = kwargs[k]
    return ret


class BaseHandler(tornado.web.RequestHandler):
    '''
    base handler implement get current user
    '''

    def get_current_user(self):
        user = self.get_secure_cookie("id", max_age_days=7)
        if not user:
            return None
        return user

    def data_received(self, chunk):
        pass


class LoginHandler(BaseHandler):
    '''
    handle login page
    '''

    def get(self, *args, **kwargs):
        if self.get_current_user():
            self.redirect('/')
        else:
            self.render('login.html', **get_render_param('username', 'password', 'login', error=''))

    def post(self, *args, **kwargs):
        user = self.get_argument('user')
        pwd = self.get_argument('pwd')
        if user == 'admin'and pwd == 'admin':
            self.set_secure_cookie('id', self.get_argument('user'))
            self.redirect('/')
        else:
            self.render('login.html', **get_render_param('username', 'password', 'login', error='invalid username or password'))


BODY_BEGIN = '<body>'
BODY_END = '</body>'

DOMAINS = []  # todo: put it in database, per user
RELATIVE_PARTTEN = re.compile(r"=[\"'](/[^/].+?)+?[\"']")


def insert_string(src, input, pos):
    '''
    insert string to specific position
    '''
    return src[:pos] + input + src[pos:]


GOOGLE_PARTTEN = re.compile(r'"/url\?q=.+?"')


def forward(url, root, post_arguments={}):
    '''
    forward origin url request
    '''
    try:
        if 'http' not in url:
            url = 'http://' + url   # todo: support https
        uri = urlparse(url)
        headers = requests.utils.default_headers()
        headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                                      ' Chrome/58.0.3029.110 Safari/537.36'})
        if not post_arguments:
            resp = requests.get(url, headers=headers)
        else:
            resp = requests.post(url, data=post_arguments, headers=headers)

        if resp.ok:
            content = resp.content
            if 'text/html' in resp.headers['Content-Type']:
                for relative in RELATIVE_PARTTEN.finditer(content):
                    match = relative.group()
                    replace = insert_string(match, 'http://{}/{}'.format(root, uri.netloc.encode(resp.encoding)), 2)
                    log('relative match:{} -> {}'.format(match, replace))
                    content = content.replace(match, replace)
                for domain in DOMAINS:
                    absolute_partten = re.compile(r'[\'"](https?:)?//([\w\-]+\.)*{}/?.*?["\']'.format(domain.replace('.', r'\.')))
                    for absolute in absolute_partten.finditer(content):
                        match = absolute.group()
                        replace = match[:1] + 'http://{}/{}'.format(root, match[match.find('//') + 2:])
                        log('absolute match:{} -> {}'.format(match, replace))
                        content = content.replace(match, replace)
                if 'google' in url:  # special case for google search result
                    for href in GOOGLE_PARTTEN.finditer(content):
                        match = href.group()
                        replace = match[:match.index('&amp;')].replace('/url?q=', '').replace('%25', '%') + '"'
                        content = content.replace(match, replace)
            return True, content, resp.headers
        else:
            raise requests.HTTPError(
                '{} : {}'.format(resp.status_code, resp.reason))
    except (requests.ConnectionError, requests.HTTPError) as exp:
        return False, str(exp), None


ENHANCED = False
ACTIVES = {}


class MainHandler(BaseHandler):
    '''
    handle main page
    '''
    @tornado.web.authenticated
    def post(self, *args, **kwargs):
        origin = self.get_argument('content')
        ACTIVES[self.get_current_user()] = origin
        okey, result, headers = forward(origin, self.request.headers.get('Host'))
        if okey:
            self.set_header('Content-Type', headers['Content-Type'])
            self.write(result)
        else:
            self.redirect('/?result={}'.format(result))

    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        domains = ''
        result = ''
        try:
            result = self.get_argument('result')
        except tornado.web.MissingArgumentError:
            pass
        for domain in DOMAINS:
            domains += domain + '\n'
        self.render('main.html', **get_render_param('explorer', 'config', keyword='', enhanced=ENHANCED, result=result, domains=domains))


DOMAIN_PATTERN = re.compile(r'^(\*\.)?([\w\-]+\.)+[a-zA-Z]{2,6}$')


class ConfigHandler(BaseHandler):
    '''
    maintain config domain for redirect
    '''
    @tornado.web.authenticated
    def post(self, *args, **kwargs):
        global DOMAINS
        global ENHANCED
        ENHANCED = True if self.get_argument('enhanced') == '1' else False
        DOMAINS = self.get_argument('domains').split('\r\n')
        for domain in DOMAINS:
            if not domain:
                continue
            if not DOMAIN_PATTERN.match(domain):
                result = '[{}] is invalid'.format(domain)
                break
        result = 'Success'
        self.redirect('/?result={}'.format(result))


class WildcardHandler(BaseHandler):
    '''
    handle other request
    '''

    def _process(self):
        '''
        process wildcard request
        '''
        if '.' not in self.request.uri.split('/')[1]:   # this is a uri can not be replaced, like /foo/cd in css
            user = self.get_current_user()
            if not ACTIVES.has_key(user):
                self.redirect('/?result=user {} not launch the first request'.format(user))
                return
            uri = ACTIVES[user] + self.request.uri
        else:
            uri = self.request.uri[1:]
        okey, result, headers = forward(uri, self.request.headers.get('Host'),
                                        self.request.body_arguments if self.request.method == 'POST' else {})
        if okey:
            self.set_header('Content-Type', headers['Content-Type'])
            self.write(result)
        else:
            self.set_status(404, result)

    @tornado.web.authenticated
    def post(self, *args, **kwargs):
        log('post wildcard:{}'.format(self.request.uri))
        self._process()

    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        log('get wildcard:{}'.format(self.request.uri))
        self._process()


URL_PATTERN = [
    (r'/', MainHandler),
    (r'/login', LoginHandler),
    (r'/config', ConfigHandler),
    (r'/.+', WildcardHandler)
]


def main_loop(port):
    '''
    web server main loop
    '''
    try:
        current = os.path.dirname(__file__)
        template_path = os.path.join(current, 'templates')
        static_path = os.path.join(current, 'static')
        app = tornado.web.Application(URL_PATTERN, template_path=template_path,
                                      static_path=static_path, login_url='/login', autoreload=True,
                                      cookie_secret="maijg1049tubkj3goqjgk14jtjj34h-ugf134jf-1-=")
        app.listen(port)
        print 'serve at port {} ...'.format(port)
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        tornado.ioloop.IOLoop.instance().stop()


def main():
    '''
    main entry
    '''
    port = 80
    global DEBUG
    try:
        if len(sys.argv) >= 2:
            if sys.argv[1] == 'debug':
                DEBUG = True
            else:
                port = int(sys.argv[1])
                if port > 65535:
                    raise ValueError('port number too large')

            if len(sys.argv) == 3 and sys.argv[2] == 'debug':
                DEBUG = True

        main_loop(port)
    except ValueError:
        print '"{}" can not use as a port.'.format(port)


if __name__ == '__main__':
    main()
