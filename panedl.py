import time, os, logging
import webapp2
import mimetypes
import cgi
import configparser
import base64
import redis
import json
import jinja2

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

num_logs_page = 100

def _setGlobalVars(usr,pasw,rfresh,dbhost,dbexp):
	global USERNAME
	global PASSWORD 
	global DBHOST
	global DBEXP
	global RFRESH
	USERNAME = usr
	PASSWORD = pasw
	DBHOST = dbhost
	DBEXP = dbexp
	RFRESH = int(rfresh)

def _checkAuth(auth):
	encoded_auth = auth[1]
	username_colon_pass = base64.b64decode(encoded_auth)
	username, password = username_colon_pass.split(':')
	return username == USERNAME and password == PASSWORD

def requiresLogin(f):
	def authenticate(self):
		auth = self.request.authorization
                if auth is None or not _checkAuth(auth):
                        self.response.status_int = 401
                        self.response.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
			self.response.out.write('*** Not authorized ***')
                        return
    		f(self)
  	return authenticate

class DB:
	""" Redis Database handler """ 
	database = ''
	def __init__(self):
		self.host = str(DBHOST)
		self.port = 6379
		self.exp = int(DBEXP)
	def __connect__(self):
        	self.con = redis.Redis(host=self.host, port=self.port, db=self.database)
	def set(self, data):
        	self.__connect__()
        	self.con.set('L-'+str(time.time()), data, ex=self.exp )
	def listkeys(self):
		self.__connect__()
		keys = self.con.keys()
		return sorted(keys, reverse=True)
	def get(self, key):
		return self.con.get(key)
	def ttl(self, key):
                return self.con.ttl(key)
	def sadd(self, sname, elmt):
		self.__connect__()
		self.con.sadd( sname, elmt)
	def srem(self, sname, elmt):
		self.__connect__()
		self.con.srem( sname, elmt)
	def smembers(self, sname):
		self.__connect__()
		return self.con.smembers(sname)

class ThreatLogDB(DB):
	""" Use database name [0] """
	database = 1

class WhitelistDB(DB):
        """ Use database name [0] """
        database = 15

class StaticFileHandler(webapp2.RequestHandler):
	def get(self, path):
		abs_path = os.path.abspath(os.path.join(self.app.config.get('webapp2_static.static_file_path', 'static'), path))
		logging.debug('DEBUG: File loaded: '+str(abs_path))
		if os.path.isdir(abs_path) or abs_path.find(os.getcwd()) != 0:
			self.response.set_status(403)
			return
		try:
			logging.debug('DEBUG: Mimetype: '+str(mimetypes.guess_type(abs_path)[0]))
			self.response.headers['Content-Type'] = mimetypes.guess_type(abs_path)[0]
			f = open(abs_path, 'r')
			self.response.headers.add_header('Content-Type', mimetypes.guess_type(abs_path)[0])
			self.response.out.write(f.read())
			f.close()
		except:
			self.response.set_status(404)

class MainPage(webapp2.RequestHandler):
	def get(self):
		offset = int(self.request.get('offset', '0'))
		offset += num_logs_page
		rowcount  = 0
		rowid = ''
		r = ThreatLogDB()
		whitelist = WhitelistDB()
                keys = r.listkeys()
		num_keys = str(len(keys))
		th_whitelist = list(whitelist.smembers('threat_whitelist'))

		self.response.headers['Content-Type'] = 'text/html'
                header_values = {
                        'page_refresh': RFRESH,
			'num_keys': num_keys,
			'db_exp': DBEXP,
			'th_whitelist': th_whitelist,
			'dashboard': 'active',
                }

                header = JINJA_ENVIRONMENT.get_template('static/html/header.html')
                self.response.write(header.render(header_values))

		self.response.out.write('<div class="log-header-container"><span class="log-header">FIREWALL LOGS</span></div>')
		for  i in keys[0:offset]:
			rowcount += 1
			logs = r.get(i)
			exp = r.ttl(i)
			if rowcount == offset - num_logs_page:
				rowid = "scroll-to"
			log_table_values = {
				'index': i,
				'logs': logs,
				'exp': exp,
				'rowid': rowid,
			}

			logs = JINJA_ENVIRONMENT.get_template('static/html/log_table.html')
			self.response.write(logs.render(log_table_values))
		if int(num_keys) > int(num_logs_page):
			self.response.out.write('<p><a  href="/?offset={}">Load more</a></p>'.format(offset))
		self.response.out.write('</body></html>')


class JobsThreatUpdateSource(webapp2.RequestHandler):
	@requiresLogin
	def post(self):
		content = self.request.body
		path = self.request.path
		logging.info('uri:'+ path+' '+ content)
		logging.debug('DEBUG: '+str(self.request.authorization))
		r = ThreatLogDB()
		r = r.set(content)

class GetThreatsSources(webapp2.RequestHandler):
	""" Source list """
	def get(self):
		ip_list = []
		r = ThreatLogDB()
                keys = r.listkeys()
		whitelist = WhitelistDB()
		th_whitelist = whitelist.smembers('threat_whitelist')
		self.response.headers['Content-Type'] = 'text/plain'
		for i in keys:
			log = json.loads(r.get(i))
			ip_list.append(str(log['attacker_ip']))

		ip_list = list(dict.fromkeys(ip_list))
		ip_list = list(set(ip_list) - th_whitelist)
		ip_list_str="\n".join(ip_list)

		self.response.write('{}'.format(ip_list_str))

class AdminSetupPage(webapp2.RequestHandler):
	""" EDL whitelisting """
	@requiresLogin
	def get(self):
		RFRESH = ''
		whitelist = WhitelistDB()
		th_whitelist = list(whitelist.smembers('threat_whitelist'))

		self.response.headers['Content-Type'] = 'text/html'
		header_values = {
			'page_refresh': RFRESH,
			'admin': 'active',
		}
		content_values = {
			'th_whitelist': th_whitelist,
			}
		header = JINJA_ENVIRONMENT.get_template('static/html/header.html')
		content = JINJA_ENVIRONMENT.get_template('static/html/admin.html')
		self.response.write(header.render(header_values))
		self.response.write(content.render(content_values)) 
		self.response.out.write('</body></html>')
	def post(self):
		whitelist_add = self.request.get('whitelist_add')
		whitelist_remove = self.request.get('whitelist_remove')
		whitelist = WhitelistDB()
		if whitelist_add:
			whitelist.sadd('threat_whitelist', whitelist_add)
		if whitelist_remove:
			whitelist.srem('threat_whitelist', whitelist_remove)
		self.get()


application = webapp2.WSGIApplication([
	('/', MainPage),
	('/admin/setup', AdminSetupPage),
	('/jobs/threat_update_source', JobsThreatUpdateSource ),
	('/lists/threats_sources.txt', GetThreatsSources ),
	(r'/static/(.+)', StaticFileHandler),
], debug=True)


def main():
	filename = str(__file__)
	config = configparser.ConfigParser()
	config.sections()
	config.read('config.ini')

	_setGlobalVars(config['MAIN']['username'], config['MAIN']['password'], config['MAIN']['page-refresh'], config['REDIS']['dbhost'], config['REDIS']['expiry'])
	host = config['MAIN']['listen']
	port = config['MAIN']['port']
	log_file = config['LOGGING']['file']
	log_level = config['LOGGING']['level']

	logging.basicConfig(filename=log_file, filemode='w', format='%(asctime)s - %(filename)s - %(name)s[%(process)d] - %(message)s', level=int(log_level))
	logging.info('Starting webserver - '+host+':'+port)

	from paste import httpserver
	httpserver.serve(application, host=host, port=port)

if __name__ == '__main__':
	main()

