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
from pprint import pprint

import smtplib
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase

app = Flask(__name__)

# Local config
#
app.secret_key = 'secret'

dbHost="localhost"
dbUser="root"
dbName="arf"

def is_authorized():
    authorizedUser=True
    if not request.environ['SERVER_SOFTWARE'][:8]=="Werkzeug":
        if not authorizedUser:
            abort(401)

# end of local config

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
    msg = MIMEBase('multipart','report')
    msg.set_param('report-type','feedback-report',requote=False)

    #msg["To"] = "fmartin@tst.linkedin.com,franck@tst.linkedin.com";
    msg["To"] = str(item['emailAbuse'])
    msg["From"] = "postmaster@linkedin.com";
    msg["Subject"] = "Abuse report for: "+str(item['subject'])

    text = "This is an email in the abuse report format for an email message received from \r\n"
    text = text+"IP "+str(item['sourceIp'])+" "+str(item['sourceDomain'])+" on "+str(item['arrivalDate'])+".\r\n"
    text = text+"This report likely indicates a compromised machine and may contain URLs to malware, treat with caution!\r\n"
    text = text+"For more information about this format please see http://tools.ietf.org/html/rfc6591.\r\n";

    msgtxt = MIMEText(text)
    msg.attach(msgtxt)

    msgreport = MIMEBase('message', "feedback-report")
    msgreport.set_charset("US-ASCII")
    
    text = "Feedback-Type: fraud\r\n"
    text = text + "User-Agent: pyforensic/1.0\r\n"
    text = text + "Version: 1.0\r\n"
    text = text + "Source-IP: "+str(item['sourceIp'])+"\r\n"
    text = text + "Arrival-Date: "+str(item['arrivalDate'])+"\r\n"

    msgreport.set_payload(text)
    msg.attach(msgreport)

    msgrfc822 = MIMEBase('message', "rfc822")
    msgrfc822.add_header('Content-Disposition','inline')
    msgrfc822.set_payload(item['content'])
    
    msg.attach(msgrfc822)

    s = smtplib.SMTP('mail.corp.linkedin.com')
    toList = msg["To"].split(",")
    s.sendmail(msg["From"], toList, msg.as_string())
    s.quit()


@app.before_request
def before_request():
    g.db=MySQLdb.connect(host=dbHost,user=dbUser,db=dbName)
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
def url(pattern="%",limit=50):
    strSql='select urlId, INET_NTOA(urlIp) as Ip, urlAsn, url from url where url like "%s" order by urlId desc limit %s' % (pattern,limit)
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(urlId=row[0], Ip=row[1], urlAsn=row[2], url=row[3]) for row in cur.fetchall()]
    cur.close()
    title = "URLs with a sspecific pattern"
    return render_template('url_list.html', entries=entries, title=title)

@app.route('/url/subject/pattern/<pattern>')
def urllistSubject(pattern="%"):
    strSql='select distinct c.urlId as urlId, INET_NTOA(c.urlIp) as Ip, c.urlAsn as urlAsn, c.url as url from arfEmail a, emailUrl b, url c where a.emailId=b.emailId and b.urlId = c.urlId and a.subject like "%s" order by urlId desc' % pattern
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(urlId=row[0], Ip=row[1], urlAsn=row[2], url=row[3]) for row in cur.fetchall()]
    cur.close()
    title = "URLs from emails with a sepcific subject"
    return render_template('url_list.html', entries=entries, title=title)

@app.route('/email/')
@app.route('/email/type/')
@app.route('/email/type/<emailType>')
@app.route('/email/type/<emailType>/limit/')
@app.route('/email/type/<emailType>/limit/<int:limit>')
def displayMailList(emailType=None,limit=50):
    strSqlEmailType=""
    if emailType is not None:
        if emailType=="normal" or emailType=="bounce" or emailType=="auto-replied":
            strSqlEmailType='and emailType="%s"' % emailType    
    strSql='select e.emailId as emailId, reported, arrivalDate, d.domain as reportedDomain, f.domain as sourceDomain, deliveryResult, subject from arfEmail e, domain d, domain f where e.reportedDomainID=d.domainId and e.sourceDomainId=f.domainId %s order by emailId desc limit %s' % (strSqlEmailType,limit)
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(emailId=row[0], reported=row[1], arrivalDate=row[2], reportedDomain=row[3], sourceDomain=row[4], deliveryResult=row[5], subject=row[6]) for row in cur.fetchall()]
    cur.close()
    title = "Email List" 
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
def displayMailListSubject(subject="%",limit=50):
    strSql='select distinct e.emailId as emailId, reported, arrivalDate, d.domain as reportedDomain, f.domain as sourceDomain, deliveryResult, subject from arfEmail e, domain d, domain f where e.reportedDomainID=d.domainId and e.sourceDomainId=f.domainId and e.subject like "%s" order by emailId desc limit %s' % (subject,limit)
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(emailId=row[0], reported=row[1], arrivalDate=row[2], reportedDomain=row[3], sourceDomain=row[4], deliveryResult=row[5], subject=row[6]) for row in cur.fetchall()]
    cur.close()
    title = "Emails with a specific subject"
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
    title = "Emails that contains a specific url"
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
    strSql = 'select distinct e.emailId as emailId, reported, arrivalDate, d.domain as reportedDomain, INET_NTOA(e.sourceIp) as sourceIp, f.domain as sourceDomain, deliveryResult, subject, content from arfEmail e, domain d, domain f where e.reportedDomainID=d.domainId and e.sourceDomainId=f.domainId and emailId in (%s)' % strEmailList
    cur = g.db.cursor()
    cur.execute(strSql)
    entries = [dict(emailId=row[0], reported=row[1], arrivalDate=row[2], reportedDomain=row[3], sourceIp=row[4], sourceDomain=row[5], deliveryResult=row[6], subject=row[7], content=row[8], emailAbuse="") for row in cur.fetchall()]
    cur.close()
    for item in entries:
        #find where to report abuse
        item['emailAbuse']=getEmailAbuseFromIp(item['sourceIp'])
        if item['emailAbuse']!="":
            item['emailAbuse']=item['emailAbuse']+',reportphishing@apwg.org'
        else:
            item['emailAbuse']='reportphishing@apwg.org'
            
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
    title = "Red Dawn"
    app.run(host='0.0.0.0',debug=True)
