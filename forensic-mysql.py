#!/usr/bin/env python
# encoding: utf-8

#Copyright 2012 Linkedin
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#

import imaplib, email, json, time, subprocess, os, re, urlparse, dns.resolver, dns.reversename, operator
import sys
import hashlib
import calendar
import math
from datetime import date, datetime, timedelta
from dateutil.parser import parse
import MySQLdb
import signal,os
import os
import os.path

from ConfigParser import SafeConfigParser

# local config
#
config = SafeConfigParser()
filename = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'forensic.cfg')
found=config.readfp(open(filename))

dbHost=config.get('db','dbHost')
dbUser=config.get('db','dbUser')
dbName=config.get('db','dbName')
dbPassword=config.get('db','dbPassword')

imapHost=config.get('mailbox','imapHost')
imapUser=config.get('mailbox','imapUser')
imapPassword=config.get('mailbox','imapPassword')

wldomain=config.get('dnsbl','wldomain').split(",")

networks = {}
pidfile = "forensic-mysql.pid"

# end of local config

def exitHard(exit_status):
	os.unlink(pidfile)
	sys.exit(exit_status)

def writePid():
	pid = os.getpid()

	if os.path.isfile(pidfile):
		old_pid = None
		with open(pidfile, "r") as f:
			old_pid = f.read().strip()
		try:
			os.kill(int(old_pid), 0)
		except OSError:
			print "{0} is no longer running or not owned by us".format(old_pid)
			os.unlink(pidfile)
		except ValueError:
			print "{0} is not a valid pid".format(old_pid)
			os.unlink(pidfile)
		else:
			print "{0} is still running".format(os.path.basename(__file__))
			sys.exit(1)

	with open(pidfile, "w") as f:
		f.write(str(pid))

match_urls = re.compile(r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""", re.DOTALL)

def handleTimeOut(signum, frame0):
   raise TimeoutError("taking too long")

def addressInNetwork(ip, net):
   import socket,struct
   ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
   netstr, bits = net.split('/')
   netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
   mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
   return (ipaddr & mask) == (netaddr & mask)

def domainIsSubDomain(subdomain):
	isSubDomain = False
	for domain in domains:
		if subdomain==domain or subdomain.endswith("."+domain) :
			isSubDomain = True
			break
	return isSubDomain

def getIp4ToAsn(ip):
	asn = 0
	try:
		(ip1,ip2,ip3,ip4) = ip.split(".")
		query = "%s.%s.%s.%s.origin.asn.cymru.com" % (ip4,ip3,ip2,ip1)
		reportanswers = dns.resolver.query(query, 'TXT')
		res = reportanswers[0].to_text()
		asn = long(res.split("|")[0][1:])
	except:
		pass
	return asn

def getIp4ToAsnCc(ip):
	asn = 0
	cc = "ZZ"
	try:
		(ip1,ip2,ip3,ip4) = ip.split(".")
		query = "%s.%s.%s.%s.origin.asn.cymru.com" % (ip4,ip3,ip2,ip1)
		reportanswers = dns.resolver.query(query, 'TXT')
		res = reportanswers[0].to_text()
		asn = long(res.split("|")[0][1:])
		cc = res.split("|")[2][1:3]
	except:
		pass
	
	return asn,cc

def getDomainId(db,domain):
	if domain is None:
		domain = ""
	try:
		domain = domain.lower()
		strSql = "insert into domain (domain) values('{0}')".format(db.escape_string(domain))
		db.query(strSql)
		db.commit()
	except:
		pass
	strSql = "select domainId from domain where domain='{0}'".format(db.escape_string(domain))
	db.query(strSql)
	result = db.store_result()
	if result is not None:
		row = result.fetch_row(1,1)[0]
		domainId = row['domainId']
	else:
		domainId = 0
	return domainId

def getEmailLocalId(db,local):
	if local is None:
		local = ""
	try:
		local = local.lower()
		strSql = "insert into emailLocal (emailLocal) values('{0}')".format(db.escape_string(local))
		db.query(strSql)
		db.commit()
	except:
		pass
	strSql = "select emailLocalId from emailLocal where emailLocal='{0}'".format(db.escape_string(local))
	db.query(strSql)
	result = db.store_result()
	if result is not None:
		row = result.fetch_row(1,1)[0]
		emailLocalId = row['emailLocalId']
	else:
		emailLocalId = 0
	return emailLocalId

def getUrl(db,emailId,arrivalDate,listurl):
	for urlitem in listurl:
		(ip,hostname,url) = urlitem
		urlAsn = getIp4ToAsn(ip)
		urlDomainId = getDomainId(db,hostname)
		strSql1=""
		found=False
		url = db.escape_string(url)
		if len(url)>999:
			url = url[:999]
		strSql = "select urlId from url where url='{0}'".format(db.escape_string(url))
		db.query(strSql)
		result = db.store_result()
		if result is not None:
			try:
				row = result.fetch_row(1,1)[0]
				urlId = row['urlId']
				found=True
			except:
				urlId = 0
		if not found:
			urlId=0
			try:
				cur = db.cursor()
				strSql1 = "insert into url (firstSeen,lastSeen,urlIp,urlDomainId,urlAsn,url) values('{0}','{1}',INET_ATON('{2}'), {3}, {4},'{5}')".format(
						db.escape_string(arrivalDate),
						db.escape_string(arrivalDate),
						db.escape_string(ip),
						db.escape_string(urlDomainId),
						db.escape_string(urlAsn),
						db.escape_string(url))
				cur.execute(strSql1)
				urlId=cur.lastrowid
				db.commit()
				cur.close()
			except:
				pass
		try:
			strSql = "update url set lastSeen='{0}' where urlId={1}".format(
				db.escape_string(arrivalDate),
				db.escape_string(urlId))
			db.query(strSql)
			db.commit()
		except:
			print strSql
			pass
		try:
			strSql = "insert into emailUrl (emailId,urlId) values({0}, {1})".format(
				db.escape_string(emailId),
				db.escape_string(urlId))
			db.query(strSql)
			db.commit()
		except:
			pass

def getFile(db,emailId,arrivalDate,md5):
	for md5Item in md5:
		hash = md5item[0]
		filename = md5item[1][:255]
		print hash,filename
		try:
			strSql = "insert into file (firstSeen,lastSeen,hash,filename) values('{0}','{1}','{2}','{3}')".format(
					db.escape_string(arrivalDate),
					db.escape_string(arrivalDate),
					db.escape_string(hash),
					db.escape_string(filename))
			db.query(strSql)
			db.commit()
		except:
			pass
		strSql = "select fileId from file where hash='{0}'".format(db.escape_string(hash))
		db.query(strSql)
		result = db.store_result()
		if result is not None:
			row = result.fetch_row(1,1)[0]
			fileId = row['fileId']
		else:
			fileId = 0
		try:
			strSql = "update file set lastSeen='{0}' where urlId={1}".format(
					db.escape_string(arrivalDate),
					db.escape_string(fileId))
			db.query(strSql)
			db.commit()
		except:
			print strSql
			pass
		try:
			strSql = "insert into emailFile (emailId,fileId) values({0}, {1})".format(
				db.escape_string(emailId),
				db.escape_string(fileId))
			db.query(strSql)
			db.commit()
		except:
			pass	

writePid()
match_emails = re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b',re.IGNORECASE)

liyear=0
limonth=0
liday=0

lioldyear=0
lioldmonth=0
lioldday=0

lidate=time.gmtime()

today = date.today()
yesterday = today - timedelta(days=3)
sentsince = '(SENTSINCE %s NOT SEEN)' % yesterday.strftime('%d-%b-%Y')

print sentsince

topsendingip={}
topurlip={}
topurl={}

try:
	db=MySQLdb.connect(host=dbHost,user=dbUser,passwd=dbPassword,db=dbName)
	db.autocommit(True)
except Exception as e:
	print "Could not connect to the database"
	print e
	exitHard(1)

try:
	imap = imaplib.IMAP4_SSL(imapHost, port=imapPort)
	imap.login(imapUser, imapPassword)
except Exception as e:
	print "Couldn't log in to {0} via IMAP on port {1}".format(imapHost, imapPort)
	print e
	exitHard(1)

r, data = imap.select('INBOX')
r, data = imap.search(None, sentsince)
#r, data = imap.search(None,'ALL')
ids = data[0]
id_list = ids.split()
for num in id_list:
	r, data = imap.fetch(num, '(RFC822)')
	msg = email.message_from_string(data[0][1])
	feedbackreport = ""
	orgmsg = ""
	lisubject = ""
	lifrom = ""
	liautosubmitted = ""
	rfc822Found = False
	bounce=False
	for part in msg.walk():
		if part.get_content_type() == 'message/feedback-report':
			feedbackreport = part.get_payload()
			feedbackreportitems = feedbackreport[0].items()
		elif part.get_content_type() == 'message/rfc822' and not rfc822Found:
			msg2 = part.get_payload()
			orgmsg = msg2[0].as_string()
			lisubject = msg2[0].get('Subject')
			lifrom = msg2[0].get('From')
			liautosubmitted = msg2[0].get('Auto-submitted')
			rfc822Found = True
			
	limsg = {}
	if lisubject is not None:
		u_subject = unicode(lisubject,errors='replace')
		limsg ['subject'] = u_subject.encode("ascii",'xmlcharrefreplace')
	else:
		limsg ['subject'] = ""

	if limsg ['subject'].find("Out of Office") >=0 :
		liautosubmitted="auto-replied"
	if limsg ['subject'].find("Automatic reply") >=0 :
		liautosubmitted="auto-replied"
	if limsg ['subject'].find("Auto Reply:") >=0 :
		liautosubmitted="auto-replied"
	if limsg ['subject'].find("Autoreply") >=0 :
		liautosubmitted="auto-replied"
	if limsg ['subject'].find("Delivery Failure") >=0 :
		bounce=True
	if limsg ['subject'].find("failure notice") >=0 :
		bounce=True
	if limsg ['subject'].find("DELIVERY FAILURE") >=0 :
		bounce=True


	limsg ['feedbackType'] = ""
	limsg ['sourceIP'] = ""
	limsg ['inNetwork'] = False
	limsg ['mailFrom'] = ""
	if lifrom is not None:
		u_from = unicode(lifrom,errors='replace')
		limsg ['from'] = u_from.encode("ascii",'xmlcharrefreplace')
	else:
		limsg ['from'] = ""

	limsg ['userAgent'] = ""	
	limsg ['date'] = datetime.now()
	limsg ['messageId'] = ""
	u_orgmsg = unicode(orgmsg,errors='replace')
	limsg ['msg'] = u_orgmsg.encode("ascii",'xmlcharrefreplace')

	isInNetwork = False	
	for item in feedbackreportitems:
		if item[0] == 'Source-IP':
			ip = str(item[1])
			limsg ['sourceIP'] = unicode(ip,errors='replace')
			for network in networks:
				if addressInNetwork(ip,network):
#					print 'found!'
					isInNetwork = True
					break;
		if item[0] == 'Arrival-Date':
			try:
				lidate = parse(unicode(item[1],errors='replace').encode("ascii",'replace'))
				listrdate = str(calendar.timegm(lidate.utctimetuple()))
			except:
				listrdate = str(calendar.timegm(lidate.utctimetuple()))
			limsg['date'] = listrdate
		if item[0] == 'Original-Mail-From':
			limsg ['mailFrom'] = unicode(item[1],errors='replace')
		if item[0] == 'User-Agent':
			limsg ['userAgent'] = unicode(item[1],errors='replace')
		if item[0] == 'Feedback-Type':
			limsg ['feedbackType'] = unicode(item[1],errors='replace')
		if item[0] == 'Original-Rcpt-To':
			limsg ['Original-Rcpt-To'] = unicode(item[1],errors='replace')
		if item[0] == 'Reported-Domain':
			limsg ['Reported-Domain'] = unicode(item[1],errors='replace')
		if item[0] == 'Delivery-Result':
			limsg ['Delivery-Result'] = unicode(item[1],errors='replace')
		if item[0] == 'Message-ID':
			limsg ['messageId'] = unicode(item[1],errors='replace')
		if item[0] == 'Authentication-Results':
			limsg ['Authentication-Results'] = unicode(item[1],errors='replace')

	limsg ['inNetwork'] = isInNetwork
	
	if limsg ['mailFrom']=="":
		bounce=True
	
	try:
		print num
		print 'message: %s %s %s mailfrom:%s from:%s rcptto:%s [%s]' % (limsg ['Reported-Domain'],time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime(int(limsg['date']))),limsg ['sourceIP'],limsg ['mailFrom'],limsg ['from'],limsg ['Original-Rcpt-To'],limsg ['subject'])
	except:
		print 'message: error, %s' % num
	#print orgmsg
		#print "-------******************"
	urls=[]
	md5=[]
	msg3 = email.message_from_string(orgmsg)
	for orgpart in msg3.walk():
		ctype = orgpart.get_content_type()
		if orgpart.get_content_maintype() == 'text':
			orgmsgpart = orgpart.get_payload(decode=True)

			signal.signal(signal.SIGALRM, handleTimeOut)
			signal.alarm(30)
			try:
				urls = urls + match_urls.findall(orgmsgpart)
			except Exception, err:
				print ' A error: %s with %s' % (str(err),orgmsgpart)
				signal.alarm(0)
		else:
			if ctype == 'message/delivery-status':
				bounce = True
			if orgpart.get_content_maintype() == 'application':
				orgmsgpart = orgpart.get_payload(decode=True)
				filename = orgpart.get_filename()
				if filename is None:
					filename = ""
				hash = hashlib.md5(orgmsgpart)
				md5item = [hash.hexdigest(),filename]
				md5 = md5 + [md5item]
				
	listurl=[]
	for url in urls:
		o = urlparse.urlparse(url[0])
		urlReport=True
		for domain in wldomain:
			if o.hostname is not None and o.hostname[-len(domain):]==domain:
				urlReport=False
		if urlReport==True:
			try:
				reportanswers = dns.resolver.query(o.hostname, 'A')
				ip = reportanswers[0].to_text()
				#except dns.exception.DNSException as e:
			except Exception, err:
				ip = ""
				print '  A error: %s' % str(err)
			listurl = listurl +[(ip,o.hostname,url[0])]

	#storing results in db
	reportedDomainId = getDomainId(db,limsg ['Reported-Domain'])
	
	try:
		(local,domain)=limsg ['mailFrom'].split('@',2)
	except:
		local = ""
		domain = ""
	
	originalMailFromLocalId = getEmailLocalId(db,local)
	originalMailFromDomainId = getDomainId(db,domain)
	
	try:
		(local,domain)=limsg ['Original-Rcpt-To'].split('@',2)
	except:
		local = ""
		domain = ""
	
	originalRcptToLocalId = getEmailLocalId(db,local)
	originalRcptToDomainId = getDomainId(db,domain)

	reverse = dns.reversename.from_address(limsg ['sourceIP'])
	try:
		reportanswers = dns.resolver.query(reverse, 'PTR')
		domain = reportanswers[0].to_text()
		if domain[-1]==".":
			domain=domain[:-1]
	except Exception, err:
		domain = ""
		print '  PTR error: %s' % str(err)

	sourceDomainId = getDomainId(db,domain)

	res = match_emails.findall(limsg ['from'])
	try:
		(local,domain)=res[0].split('@',2)
	except:
		local = ""
		domain = ""
	
	originalFromLocalId = getEmailLocalId(db,local)
	originalFromDomainId = getDomainId(db,domain)

	(sourceAsn,countryCode) = getIp4ToAsnCc(limsg ['sourceIP'])

	deliveryResult="none"
	if "dis=reject" in limsg ['Authentication-Results']:
		deliveryResult="reject"
	if "dis=quarantine" in limsg ['Authentication-Results']:
		deliveryResult="quarantine"

	try:
		arrivalDate = time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime(int(limsg['date'])))
		strSql = "INSERT INTO arfEmail("
		strSql = strSql + "feedbackType,"
		strSql = strSql + "emailType,"
		strSql = strSql + "originalMailFromLocalId, originalMailFromDomainId,originalRcptToLocalId,originalRcptToDomainId,"
		strSql = strSql + "arrivalDate,messageId,authenticationResults,sourceIp, sourceDomainId, sourceAsn, countryCode,"
		strSql = strSql + "deliveryResult,"
		strSql = strSql + "reportedDomainId,"
		strSql = strSql + "originalFromLocalId, originalFromDomainId,"
		strSql = strSql + "subject,content)"
		strSql = strSql + " VALUES("
		strSql = strSql + "'%s'," % db.escape_string(limsg['feedbackType'])
		if bounce:
			strSql = strSql + "'bounce',"
		elif liautosubmitted == "auto-replied":
			strSql = strSql + "'auto-replied'," 
		else:
			strSql = strSql + "'normal',"
		strSql = strSql + "%s,%s," % (db.escape_string(originalMailFromLocalId),
			db.escape_string(originalMailFromDomainId))
		strSql = strSql + "%s,%s," % (db.escape_string(originalRcptToLocalId),
			db.escape_string(originalRcptToLocalId))
		strSql = strSql + "'%s','%s','%s',INET_ATON('%s'),%s," % (db.escape_string(arrivalDate),
			db.escape_string(limsg['messageId']),
			db.escape_string(limsg['Authentication-Results']),
			db.escape_string(limsg['sourceIP']),
			db.escape_string(sourceDomainId))
		strSql = strSql + "%s,'%s'," % (db.escape_string(sourceAsn),
			db.escape_string(countryCode))
		strSql = strSql + "'%s'," % (db.escape_string(deliveryResult))
		strSql = strSql + "%s," % (db.escape_string(reportedDomainId))
		strSql = strSql + "%s,%s," % (db.escape_string(originalFromLocalId),
			db.escape_string(originalFromDomainId))
		strSql = strSql + "'%s','%s'" % (db.escape_string(limsg ['subject']),db.escape_string(limsg['msg']))
		strSql = strSql + ")"
		#print strSql
		cur = db.cursor()
		cur.execute(strSql)
		emailId = cur.lastrowid
		db.commit()
		cur.close()
		print emailId,
		print str(len(listurl)),
		getUrl(db,emailId,arrivalDate,listurl)
		print "1 ",
		getFile(db,emailId,arrivalDate,md5)
		print "2 ",
		imap.store(num,'+FLAGS', '\\Seen')
		imap.store(num,'+FLAGS', '\\Deleted')
		print "3"
	except:
		print "error, cannot store info in db\n"
	print "-------******************"
	if math.fmod(float(num),4000) == 0 :
		break
print "Expunging now"
imap.expunge()
imap.logout()

os.unlink(pidfile)
