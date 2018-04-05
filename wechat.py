#encoding=utf-8

import tornado.web
import tornado.options
import tornado.httpserver
import tornado.ioloop
import hashlib
import xmltodict
import time
import json
import tornado.gen
import datetime
import os

from tornado.httpclient import AsyncHTTPClient,HTTPRequest
from tornado.options import define, options
from tornado.web import RequestHandler
from urllib import quote


WECHAT_TOKEN = "填写配置的token"
WECHAT_APP_ID = "填写测试号里的appid"
WECHAT_APP_SECRET = "填写测试号里的appsecret"

define("port", default = 8000, type = int, help = "")

class AccessToken(object):
	'''微信借口调用Token'''
	_access_token = {
		"token":"",
		"update_time":datetime.datetime.now()
	}

	@classmethod
	@tornado.gen.coroutine
	def update_access_token(cls):
		'''更新access_token'''
		client = AsyncHTTPClient()
		url = "https://api.weixin.qq.com/cgi-bin/token?" \
		"grant_type=client_credential&appid=%s&secret=%s" % (WECHAT_APP_ID, WECHAT_APP_SECRET)
		resp = yield client.fetch(url)
		ret = json.loads(resp.body)
		token = ret.get("access_token")
		if token:
			cls._access_token["token"] = token
			cls._access_token["update_time"] = datetime.datetime.now()

	@classmethod
	@tornado.gen.coroutine
	def get_access_token(cls):
		'''获取access_token'''
		if not cls._access_token["token"] or (datetime.datetime.now() - cls._access_token["update_time"]) >= 6600:
			yield cls.update_access_token()
		raise tornado.gen.Return(cls._access_token["token"])


class BaseHandler(RequestHandler):
	def prepare(self):
		'''开发者验证接口'''
		signature = self.get_argument("signature")
		timestamp = self.get_argument("timestamp")
		nonce = self.get_argument("nonce")
		tmp = [WECHAT_TOKEN, timestamp, nonce]
		tmp.sort()
		tmp = "".join(tmp)
		real_signature = hashlib.sha1(tmp).hexdigest()
		if signature != real_signature:
			self.send_error(403)


class WechatHandler(BaseHandler):
	'''微信接入接口'''
	def get(self):
		'''开发者验证接口'''
		echostr = self.get_argument("echostr")
		self.write(echostr)

	def post(self):
		'''收发消息接口'''
		req_xml = self.request.body
		req = xmltodict.parse(req_xml)['xml']
		msg_type = req.get("MsgType")
		if msg_type == "event":
			if req.get("Event") == "subscribe":
				resp = {
				"ToUserName":req.get("FromUserName", ""),
				"FromUserName":req.get("ToUserName", ""),
				"CreateTime":int(time.time()),
				"MsgType":"text",
				"Content":"Thanks for your subscribe!"
				}
				if req.get("EventKey") != None:
					resp["Content"] += "sid:"
					resp["Content"] += req.get("EventKey")[8:]
			elif req.get("Event") == "SCAN":
				resp = {
				"ToUserName":req.get("FromUserName", ""),
				"FromUserName":req.get("ToUserName", ""),
				"CreateTime":int(time.time()),
				"MsgType":"text",
				"Content":"sid:%s" % req.get("EventKey")
				}
			else:
				resp = None
			
		elif msg_type == "text":
			resp = {
				"ToUserName":req.get("FromUserName", ""),
				"FromUserName":req.get("ToUserName", ""),
				"CreateTime":int(time.time()),
				"MsgType":"text",
				"Content":req.get("Content", ""),
			}
		elif msg_type == "voice":
			resp = {
				"ToUserName":req.get("FromUserName", ""),
				"FromUserName":req.get("ToUserName", ""),
				"CreateTime":int(time.time()),
				"MsgType":"voice",
				"Voice":{
					"MediaId":req.get("MediaId", ""),
				}
			}
		elif msg_type == "image":
			resp = {
				"ToUserName":req.get("FromUserName", ""),
				"FromUserName":req.get("ToUserName", ""),
				"CreateTime":int(time.time()),
				"MsgType":"image",
				"Image":{
					"MediaId":req.get("MediaId", ""),
				}
			}
		else:
			resp = {
				"ToUserName":req.get("FromUserName", ""),
				"FromUserName":req.get("ToUserName", ""),
				"CreateTime":int(time.time()),
				"MsgType":"text",
				"Content":"I love you!",
			}
		resp_xml = xmltodict.unparse({"xml":resp})
		self.write(resp_xml)

class QrcodeHandler(RequestHandler):
	'''获取带参数的二维码接口'''
	@tornado.gen.coroutine
	def get(self):
		scene_id = self.get_argument("sid")
		try:
			access_token = yield AccessToken.get_access_token()
		except Exception as e:
			self.write("msgerr:%s" % e)
		url = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=%s" % access_token
		client = AsyncHTTPClient()
		req_data = {"action_name": "QR_LIMIT_SCENE", "action_info": {"scene": {"scene_id": scene_id}}}
		req = HTTPRequest(
			url = url, 
			method = "POST", 
			body = json.dumps(req_data)
			)
		resp = yield client.fetch(req)
		dict_data = json.loads(resp.body)
		if "errcode" in dict_data:
			self.write("errmsg: get qrcode failed")
		else:
			ticket = dict_data["ticket"]
			qrcode_url = dict_data["url"]
			self.write('<img src="https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=%s"><br/>' % ticket)
			self.write('<p>%s</p>' % qrcode_url)


class ProfileHandler(RequestHandler):
	'''微信网页授权接口'''
	@tornado.gen.coroutine
	def get(self):
		code = self.get_argument("code")
		if not code:
			self.write("未授权")
			return
		client = AsyncHTTPClient()
		url = "https://api.weixin.qq.com/sns/oauth2/access_token?" \
		"appid=%s&secret=%s&code=%s&grant_type=authorization_code" % (WECHAT_APP_ID, WECHAT_APP_SECRET, code)
		resp = yield client.fetch(url)
		dict_data = json.loads(resp.body)
		if "errmsg" in dict_data:
			self.write("error occur")
		else:
			access_token = dict_data["access_token"]
			openid = dict_data["openid"]
			url = "https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s&lang=zh_CN" % (access_token, openid)
			resp = yield client.fetch(url)
			user_data = json.loads(resp.body)
			if "errmsg" in user_data:
				self.write("error occur again")
			else:
				self.render("index.html", user = user_data)


class CreateMenuHandler(RequestHandler):
	'''创建自定义菜单接口'''
	@tornado.gen.coroutine
	def get(self):
		access_token = yield AccessToken.get_access_token()
		if not access_token:
			self.write("access_token error")
		else:
			menu_data = {
				"button":[
					{
					"type": "view",
					"name": "view test",
					"url": "https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_base&state=1#wechat_redirect" % (WECHAT_APP_ID, urlencode("http://配置的域名/wechat/profile"))
					},
				]			
			}
		client = AsyncHTTPClient()
		url = "https://api.weixin.qq.com/cgi-bin/menu/create?access_token=%s" % access_token
		req = HTTPRequest(
				url = url,
				method = "POST",
				body = json.dumps(menu_data, ensure_ascii=False),
				)
		resp = yield client.fetch(req)
		ret = json.loads(resp.body)
		if ret.get("errcode") == 0:
			self.write("create successed")
		else:
			self.write(ret.get("errmsg", "create failed"))


def main():
	tornado.options.parse_command_line()
	app = tornado.web.Application(
		[
			(r"/wechat", WechatHandler),
			(r"/qrcode", QrcodeHandler),
			(r"/wechat/profile", ProfileHandler),
			(r"/wechat/menu", CreateMenuHandler),
		],
		template_path = os.path.join(os.path.dirname(__file__), "template"),
	)
	http_server = tornado.httpserver.HTTPServer(app)
	http_server.listen(options.port)
	tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
	main()
