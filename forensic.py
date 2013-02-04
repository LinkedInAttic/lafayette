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

from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash, Response, request
import MySQLdb
import dns.resolver
import os
from pprint import pprint
from datetime import date, datetime, timedelta
import dns.resolver

from ConfigParser import SafeConfigParser

import smtplib
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase

from forensic_auth import is_authorized

app = Flask(__name__)

# Local config
#
config = SafeConfigParser()
filename = os.path.join(app.root_path, 'forensic.cfg')
found=config.readfp(open(filename))

app.secret_key = config.get('web','secret_key')
reportSender = config.get('web','reportSender')
mailSmtp = config.get('web','mailSmtp')

dbHost=config.get('db','dbHost')
dbUser=config.get('db','dbUser')
dbName=config.get('db','dbName')
dbPassword=config.get('db','dbPassword')

# end of local config

def getAsnInfo(asn):
    resAsn = ""
    countryCode = ""
    rir = ""
    createDate =""
    name = ""
    try:
        query = "AS%s.asn.cymru.com" % (asn)
        reportanswers = dns.resolver.query(query, 'TXT')
        info = reportanswers[0].to_text()[1:-1]
        (resAsn,countryCode,rir,createDate,name) = info.split("|",4)
    except:
        pass
    return (resAsn,countryCode,rir,createDate,name)

def getEmailAbuseFromAsn(asn):
    res=""
    strSql="select email from asn where asn=%s" % str(asn)
    g.db.query(strSql)
    result = g.db.store_result()
    if result is not None:
        try:
            row = result.fetch_row(1,1)[0]
            res = row['email']
        except:
            res = ""
    return res

def getEmailAbuseFromIp(ip):
    res=""
    try:
        (ip1,ip2,ip3,ip4) = ip.split(".")
        query = "%s.%s.%s.%s.abuse-contacts.abusix.org" % (ip4,ip3,ip2,ip1)
        reportanswers = dns.resolver.query(query, 'TXT')
        res = reportanswers[0].to_text()
        res = res[1:-1]
    except:
        pass
    return res

def sendArf(item):
    global reportSender
    global mailSmtp

    msg = MIMEBase('multipart','report')
    msg.set_param('report-type','feedback-report',requote=False)

    #msg["To"] = "fmartin@tst.linkedin.com,franck@tst.linkedin.com";
    msg["To"] = str(item['emailAbuse'])
    msg["From"] = reportSender
    msg["Subject"] = "Abuse report for: "+str(item['subject'])

    text = "This is an email in the abuse report format (ARF) for an email message received from \r\n"
    text = text+"IP "+str(item['sourceIp'])+" "+str(item['sourceDomain'])+" on "+str(item['arrivalDate'])+" UTC.\r\n"
    text = text+"This report likely indicates a compromised machine and may contain URLs to malware, treat with caution!\r\n\r\n"
    text = text+"The attached email was selected amongst emails that failed DMARC,\r\n"
    text = text+"therefore it indicates that the author tried to pass for someone else\r\n"
    text = text+"indicating fraud and not spam. The faster you fix or isolate the compromised machine, \r\n"
    text = text+"the better you protect your customers or members and the Internet at large.\r\n\r\n"
    text = text+"This ARF report contains all the information you will need to asses the problem.\r\n"
    text = text+"For more information about this format please see http://tools.ietf.org/html/rfc6591.\r\n";

    msgtxt = MIMEText(text)
    msg.attach(msgtxt)

    msgreport = MIMEBase('message', "feedback-report")
    msgreport.set_charset("US-ASCII")
    
    text = "Feedback-Type: fraud\r\n"
    text = text + "User-Agent: pyforensic/1.0\r\n"
    text = text + "Version: 1.0\r\n"
    text = text + "Source-IP: "+str(item['sourceIp'])+"\r\n"
    text = text + "Arrival-Date: "+str(item['arrivalDate'])+" UTC\r\n"

    msgreport.set_payload(text)
    msg.attach(msgreport)

    msgrfc822 = MIMEBase('message', "rfc822")
    msgrfc822.add_header('Content-Disposition','inline')
    msgrfc822.set_payload(item['content'])
    
    msg.attach(msgrfc822)

    s = smtplib.SMTP(mailSmtp)
    toList = msg["To"].split(",")
    s.sendmail(msg["From"], toList, msg.as_string())
    s.quit()


@app.before_request
def before_request():
    g.db=MySQLdb.connect(host=dbHost,user=dbUser,passwd=dbPassword,db=dbName,charset = "utf8",use_unicode = True)
    g.db.autocommit(True)
    is_authorized()

@app.teardown_request
def teardown_request(exception):
    g.db.close()

@app.route('/')
def home():
    title = "Home"
    return render_template('home.html',title=title)

@app.route('/email/id/<int:emailId>')
def displayMessage(emailId):
    strSql="select content from arfEmail where emailId=%s" % emailId
    g.db.query(strSql)
    result = g.db.store_result()
    if result is not None:
        row = result.fetch_row(1,1)[0]
        content = row['content']
    else:
        content = "No email found for emailId=%s" % emailId
    return Response(content, mimetype='text/plain')

@app.route('/url/')
@app.route('/url/pattern/')
@app.route('/url/pattern/<pattern>')
@app.route('/url/pattern/<pattern>/limit/')
@app.route('/url/pattern/<pattern>/limit/<int:limit>')
@app.route('/url/pattern/<pattern>/days/<int:days>')
@app.route('/url/pattern/<pattern>/days/<int:days>/daysago/<int:daysago>')
@app.route('/url/days/<int:days>')
@app.route('/url/days/<int:days>/daysago/<int:daysago>')
def url(pattern="%",limit=50,days=0,daysago=0):
    strSqlDate = ''
    strSqlLimit = ''
    titleDate = ''
    titleLimit = ''
    if days>0:
        today = datetime.utcnow()
        today = today.date()
        firstday = today - timedelta(days+daysago)
        lastday = today - timedelta(daysago)
        strSqlDate = 'lastSeen >="%s" and lastSeen <="%s 23:59:59" and ' % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
        titleDate = ' %s - %s UTC ' % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
        limit = 0

    if limit>0:
        strSqlLimit = 'limit %s' % limit
        titleLimit = 'limit %s' % limit

    strSql='select urlId, firstSeen, lastSeen, INET_NTOA(urlIp) as Ip, urlAsn, url from url where %s url like "%s" order by lastSeen desc %s' % (strSqlDate, pattern, strSqlLimit)
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(urlId=row[0], firstSeen=row[1], lastSeen=row[2], Ip=row[3], urlAsn=row[4], url=row[5]) for row in cur.fetchall()]
    cur.close()
    title = "URLs with the pattern '%s' %s%s" % (pattern, titleDate, titleLimit)
    return render_template('url_list.html', entries=entries, title=title)

@app.route('/url/subject/pattern/<pattern>')
def urllistSubject(pattern="%"):
    strSql='select distinct c.urlId as urlId, c.firstSeen, c.lastSeen, INET_NTOA(c.urlIp) as Ip, c.urlAsn as urlAsn, c.url as url from arfEmail a, emailUrl b, url c where a.emailId=b.emailId and b.urlId = c.urlId and a.subject like "%s" order by c.lastSeen desc' % pattern
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(urlId=row[0], firstSeen=row[1], lastSeen=row[2], Ip=row[3], urlAsn=row[4], url=row[5]) for row in cur.fetchall()]
    cur.close()
    title = "URLs from emails with a subject containing %s" % pattern
    return render_template('url_list.html', entries=entries, title=title)

@app.route('/email/')
@app.route('/email/type/')
@app.route('/email/type/<emailType>')
@app.route('/email/type/<emailType>/limit/')
@app.route('/email/type/<emailType>/limit/<int:limit>')
@app.route('/email/type/<emailType>/days/<int:days>')
@app.route('/email/type/<emailType>/days/<int:days>/daysago/<int:daysago>')
@app.route('/email/days/<int:days>')
@app.route('/email/days/<int:days>/daysago/<int:daysago>')
def displayMailList(emailType=None,limit=50,days=0,daysago=0):
    strSqlDate = ''
    strSqlLimit = ''
    titleDate = ''
    titleLimit = ''
    if days>0:
        today = datetime.utcnow()
        today = today.date()
        firstday = today - timedelta(days+daysago)
        lastday = today - timedelta(daysago)
        strSqlDate = 'arrivalDate >="%s" and arrivalDate <="%s 23:59:59" and ' % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
        titleDate = ' %s - %s UTC ' % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
        limit = 0

    if limit>0:
        strSqlLimit = 'limit %s' % limit
        titleLimit = 'limit %s' % limit

    strSqlEmailType=""
    if emailType is not None:
        if emailType=="normal" or emailType=="bounce" or emailType=="auto-replied":
            strSqlEmailType='and emailType="%s"' % emailType    
    strSql='select e.emailId as emailId, reported, arrivalDate, d.domain as reportedDomain, f.domain as sourceDomain, deliveryResult, subject from arfEmail e, domain d, domain f where %s e.reportedDomainID=d.domainId and e.sourceDomainId=f.domainId %s order by emailId desc %s' % (strSqlDate, strSqlEmailType, strSqlLimit)
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(emailId=row[0], reported=row[1], arrivalDate=row[2], reportedDomain=row[3], sourceDomain=row[4], deliveryResult=row[5], subject=row[6]) for row in cur.fetchall()]
    cur.close()
    title = "Email List%s%s" % (titleDate,titleLimit) 
    return render_template('mail_list.html', entries=entries, title=title)

@app.route('/email/urlId/<int:urlId>')
def displayMailListFromUrl(urlId=0):
    strSql='select distinct e.emailId as emailId, reported, arrivalDate, d.domain as reportedDomain, f.domain as sourceDomain, deliveryResult, subject from arfEmail e, domain d, domain f, emailUrl g where e.reportedDomainID=d.domainId and e.sourceDomainId=f.domainId and e.emailId=g.emailId and g.urlId=%s order by emailId desc' % (urlId)
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(emailId=row[0], reported=row[1], arrivalDate=row[2], reportedDomain=row[3], sourceDomain=row[4], deliveryResult=row[5], subject=row[6]) for row in cur.fetchall()]
    cur.close()
    title = "Emails containing an url"
    return render_template('mail_list.html', entries=entries, title=title)

@app.route('/email/subject/')
@app.route('/email/subject/<subject>')
@app.route('/email/subject/<subject>/limit/')
@app.route('/email/subject/<subject>/limit/<int:limit>')
@app.route('/email/subject/<subject>/days/<int:days>')
@app.route('/email/subject/<subject>/days/<int:days>/daysago/<int:daysago>')
def displayMailListSubject(subject="%",limit=50,days=0,daysago=0):
    strSqlDate = ''
    strSqlLimit = ''
    titleDate = ''
    titleLimit = ''
    if days>0:
        today = datetime.utcnow()
        today = today.date()
        firstday = today - timedelta(days+daysago)
        lastday = today - timedelta(daysago)
        strSqlDate = 'arrivalDate >="%s" and arrivalDate <="%s 23:59:59" and ' % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
        titleDate = ' %s - %s UTC ' % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
        limit = 0

    if limit>0:
        strSqlLimit = 'limit %s' % limit
        titleLimit = 'limit %s' % limit

    strSql='select distinct e.emailId as emailId, reported, arrivalDate, d.domain as reportedDomain, f.domain as sourceDomain, deliveryResult, subject from arfEmail e, domain d, domain f where %s e.reportedDomainID=d.domainId and e.sourceDomainId=f.domainId and e.subject like "%s" order by emailId desc %s' % (strSqlDate, subject, strSqlLimit)
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(emailId=row[0], reported=row[1], arrivalDate=row[2], reportedDomain=row[3], sourceDomain=row[4], deliveryResult=row[5], subject=row[6]) for row in cur.fetchall()]
    cur.close()
    title = "Emails with a subject containing %s%s%s" % (subject,titleDate,titleLimit) 
    return render_template('mail_list.html', entries=entries, title=title)

@app.route('/email/url/pattern/')
@app.route('/email/url/pattern/<pattern>')
@app.route('/email/url/pattern/<pattern>/limit/')
@app.route('/email/url/pattern/<pattern>/limit/<int:limit>')
def displayMailListUrl(pattern="%",limit=50):
    strSql='select distinct e.emailId as emailId, reported, arrivalDate, d.domain as reportedDomain, f.domain as sourceDomain, deliveryResult, subject from arfEmail e, domain d, domain f, emailUrl g, url h where e.reportedDomainID=d.domainId and e.sourceDomainId=f.domainId and e.emailId=g.emailId and g.urlId=h.urlId and h.url like "%s"  order by emailId desc limit %s' % (pattern,limit)
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(emailId=row[0], reported=row[1], arrivalDate=row[2], reportedDomain=row[3], sourceDomain=row[4], deliveryResult=row[5], subject=row[6]) for row in cur.fetchall()]
    cur.close()
    title = "Emails that contains a url with the pattern %s" % pattern
    return render_template('mail_list.html', entries=entries, title=title)

@app.route('/email/graph')
def emailGraph():
    strSql = 'select DATE_FORMAT(arrivalDate,"%Y/%m/%d %H") as hour, emailType, count(emailId) as total from arfEmail where arrivalDate >= DATE_SUB(CURDATE(),INTERVAL 72 HOUR) group by hour, emailType order by hour,emailType'
    cur = g.db.cursor()
    cur.execute(strSql)
    data = [dict(hour=row[0], emailType=row[1], total=row[2]) for row in cur.fetchall()]
    cur.close()
    entries = []
    oldHour=data[0]['hour']
    normal=0
    bounce=0
    autoreplied=0
    for item in data:
        if item['hour']!=oldHour:
            entries.append(dict(hour=oldHour[5:], normal=normal, bounce=bounce, autoreplied=autoreplied))
            normal=0
            bounce=0
            autoreplied=0
            oldHour=item['hour']
        if item['emailType'] == "normal":
            normal = item['total']
        if item['emailType'] == "bounce":
            bounce = item['total']
        if item['emailType'] =="auto-replied":
            autoreplied = item['total']
    try:
        entries.append(dict(hour=item['hour'][5:], normal=normal, bounce=bounce, autoreplied=autoreplied))
    except:
        pass
    title = "Email bar graph"
    return render_template('email_graph.html', entries=entries, title=title)

@app.route('/email/map')
@app.route('/email/map/days/<int:days>')
@app.route('/email/map/days/<int:days>/daysago/<int:daysago>')
def emailMap(days=7,daysago=0):
    today = datetime.utcnow()
    today = today.date()
    firstday = today - timedelta(days+daysago)
    lastday = today - timedelta(daysago)

    strSql = 'select countryCode, count(emailId) as total from arfEmail where arrivalDate >="%s" and arrivalDate <="%s 23:59:59" and reported=True group by countryCode;'  % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(countryCode=row[0], total=row[1]) for row in cur.fetchall()]
    maxTotal = 0
    for entry in entries:
        if entry['total']>maxTotal:
            maxTotal=entry['total']
    cur.close()

    strSql = 'select sourceAsn, count(emailId) as total from arfEmail where arrivalDate >="%s" and arrivalDate <="%s 23:59:59" and reported=True group by sourceAsn order by total desc limit 20;'  % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
    cur = g.db.cursor()
    cur.execute(strSql)
    entriesAsn = []
    for row in cur.fetchall():
        (asn,countryCode,rir,createDate,name)=getAsnInfo(row[0])
        abuseAsn=getEmailAbuseFromAsn(asn)
        entriesAsn.append(dict(sourceAsn=row[0], total=row[1], countryCode=countryCode, createDate=createDate, name=name, abuseAsn=abuseAsn))
    cur.close()

    title = 'Reported Emails Map %s - %s UTC' % (firstday.strftime('%Y-%m-%d'),lastday.strftime('%Y-%m-%d'))
    #return render_template('email_map.html', entries=entries, title=title)
    return render_template('email_map.html', entries=entries, maxTotal=maxTotal, entriesAsn = entriesAsn, title=title)

@app.route('/reportemail',methods=['GET','POST'])
def reportEmail():
    emailList = []
    nbEmailReported=0
    reporting=False
    title = "Reporting emails"
    for item in request.form:
        if item[:7]=="emailid":
            emailList.append(request.form[item])
        if item=="submit" and request.form[item]=="Send Reports":
            reporting=True
            Title = "Emails reported"
            
    strEmailList = ", ".join(emailList)
    strSql = 'select distinct e.emailId as emailId, reported, arrivalDate, d.domain as reportedDomain, INET_NTOA(e.sourceIp) as sourceIp, sourceAsn, f.domain as sourceDomain, deliveryResult, subject, content from arfEmail e, domain d, domain f where e.reportedDomainID=d.domainId and e.sourceDomainId=f.domainId and emailId in (%s)' % strEmailList
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(emailId=row[0], reported=row[1], arrivalDate=row[2], reportedDomain=row[3], sourceIp=row[4], sourceAsn=row[5], sourceDomain=row[6], deliveryResult=row[7], subject=row[8], content=row[9], emailAbuse="") for row in cur.fetchall()]
    cur.close()
    for item in entries:
        #find where to report abuse
        item['emailAbuse']=getEmailAbuseFromIp(item['sourceIp'])
        if item['emailAbuse']!="":
            item['emailAbuse']=item['emailAbuse']+',reportphishing@apwg.org'
        else:
            item['emailAbuse']='reportphishing@apwg.org'
        abuseAsn=getEmailAbuseFromAsn(item['sourceAsn'])
        if abuseAsn!="" and item['emailAbuse'].find(abuseAsn)<0:
            item['emailAbuse']=item['emailAbuse']+','+abuseAsn
            
        if reporting:
            sendArf(item)
            strSql = 'update arfEmail set reported=1 where emailId=%s' % item['emailId']
            cur = g.db.cursor()
            cur.execute(strSql)
            cur.close()
            item['reported'] = 1
            nbEmailReported = nbEmailReported+1
    if reporting:
        flash(str(nbEmailReported)+" emails have been reported to the abuse handle of each IP")
    return render_template('report_email.html', entries=entries, title=title)

if __name__ == '__main__':
    title = "Lafayette"
    app.run(host='0.0.0.0',debug=True)
