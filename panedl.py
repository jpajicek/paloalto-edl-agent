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
	def __init__(self):
		self.host = str(DBHOST)
		self.port = 6379
		self.db = 0
		self.exp = int(DBEXP)
	def __connect__(self):
        	self.con = redis.Redis(host=self.host, port=self.port, db=self.db)
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

class StaticFileHandler(webapp2.RequestHandler):
	def get(self, path):
		abs_path = os.path.abspath(os.path.join(self.app.config.get('webapp2_static.static_file_path', 'static'), path))
		logging.debug('File loaded: '+str(abs_path))
		if os.path.isdir(abs_path) or abs_path.find(os.getcwd()) != 0:
			self.response.set_status(403)
			return
		try:
			logging.debug('Mimetype: '+str(mimetypes.guess_type(abs_path)[0]))
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
		offset += 200
		rowcount  = 0
		rowid = ''
		r = DB()
                keys = r.listkeys()
		num_keys = str(len(keys))

		self.response.headers['Content-Type'] = 'text/html'
		self.response.out.write("""<!DOCTYPE html>
			<html lang="en">
			<head>
				<link rel="stylesheet" type="text/css" href="/static/stylesheets/main.css" >
				<meta http-equiv="refresh" content="{0}">
				<meta charset="UTF-8">
				<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
				<script type="text/javascript" src="/static/js/jfile.js"></script>
				<title>Palo Alto EDL Service</title>
			</head>
			<body onload="myFunction()">
			<div class="header"><b>PaloAlto External Dynamic List Service</b><br></div>
			<div class="menu-container"><ul>
				<li><a class="active" href="/">Dashboard</a></li>
  				<li><a href="/lists/threats_sources.txt">Threat EDL</a></li>
			</ul>
			</div>
			<div class="normal-size">Events recorded in database: {1} </div>
			<div class="normal-size">Database expiry: {2} seconds</div>
			<div class="normal-size">Threat updates uri:/jobs/threat_update_source
			<div class="normal-size">Page refresh: {0} seconds</div>&nbsp;
			<div class="log-header-container"><span class="log-header">FIREWALL LOGS</span></div>
			""".format(RFRESH,num_keys,DBEXP,offset))
		for  i in keys[0:offset]:
			rowcount += 1
			logs = r.get(i)
			exp = r.ttl(i)
			if rowcount == offset - 200:
				rowid = "scroll-to"
			template_values = {
				'index': i,
				'logs': logs,
				'exp': exp,
				'rowid': rowid,
			}

			logs = JINJA_ENVIRONMENT.get_template('static/html/log_table.html')
			self.response.write(logs.render(template_values))
		self.response.out.write('<p><a  href="/?offset={}">Load more</a></p>'.format(offset))
		self.response.out.write('</div></body></html>')


class JobsThreatUpdateSource(webapp2.RequestHandler):
	@requiresLogin
	def post(self):
		content = self.request.body
		path = self.request.path
		logging.info('uri:'+ path+' '+ content)
		logging.info(self.request.authorization)
		r = DB()
		r = r.set(content)

class GetThreatsSources(webapp2.RequestHandler):
	""" Source list """
	def get(self):
		self.response.headers['Content-Type'] = 'text/plain'
		self.response.write('Goodbye, World!')


application = webapp2.WSGIApplication([
	('/', MainPage),
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

