<!-- $size: 16:9 -->

Logstash Grok patterns
===

# ![](images/elastic-logstash-fw.png)

##### Logstash Grok patterns for Softnix Log Query

###### Created by [Apiwat Suksuwan](https://github.com/pobsuwan/logstash-conf)
###### Software Engineer at softnix technology co. Ltd

---

# Logstash::Intro()
###### ![](images/basic_logstash_pipeline.png)
- Logstash [Documents](https://www.elastic.co/guide/en/logstash/current/index.html)
- Logstash has [INPUT](https://www.elastic.co/guide/en/logstash/current/input-plugins.html) / [FILTER](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html) / [OUTPUT](https://www.elastic.co/guide/en/logstash/current/output-plugins.html)

---

# Logstash::Plugin()
###### Input plugin
- TCP/UDP
	- > tcp { port => 5140 codec => json }
		udp { port => 5140 codec => json }
- file
	- > file { path => ["/tmp/file.log"] }
- kafka
	- > kafka { zk_connect => "127.0.0.1:2181" topic_id => "rawlogs" }

---

# Logstash::Plugin()
###### Filter plugin
- [grok](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html)
	- [Grok Debugger](https://grokdebug.herokuapp.com/)
	- [Grok Constructor](http://grokconstructor.appspot.com/)
- [csv](https://www.elastic.co/guide/en/logstash/current/plugins-filters-csv.html)
- [mutate](https://www.elastic.co/guide/en/logstash/current/plugins-filters-mutate.html)
- [date](https://www.elastic.co/guide/en/logstash/current/plugins-filters-date.html)

---

# Logstash::Plugin()
###### Output plugin
- elasticsearch
	- > elasticsearch { hosts => [ "127.0.0.1" ] }
- file
 	- > file { path => ["/tmp/file.log"] }
- stdout
	- > stdout { codec => rubydebug { metadata => true } }

---

# Logstash::Patterns()
[Default Patterns](https://grokdebug.herokuapp.com/patterns)
###### /etc/logstash/patterns/softnix
```
COMMONSYSLOG %{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:log_source} %{SYSLOGPROG}: %{GREEDYDATA:syslog_message}

SRCIP %{IPORHOST:src_ip}
DSTIP %{IPORHOST:dst_ip}
SRCPORT %{INT:src_port}
DSTPORT %{INT:dst_port}

NETSCREENCOMMONLOG NetScreen device_id=%{WORD:device_id}%{DATA}: start_time=\"%{DATA:start_time}\" duration=%{INT:duration} policy_id=%{INT:policy_id} service=%{DATA:service} proto=%{INT:proto} src zone=%{WORD:src_zone} dst zone=%{WORD:dst_zone} action=%{WORD:action} sent=%{INT:sent} rcvd=%{INT:rcvd} src=%{SRCIP} dst=%{DSTIP}
NETSCREENLOG1 %{NETSCREENCOMMONLOG} src_port=%{SRCPORT} dst_port=%{DSTPORT} src-xlated ip=%{IPORHOST:src_xlated_ip} port=%{INT:src_xlated_port} dst-xlated ip=%{IPORHOST:dst_xlated_ip} port=%{INT:dst_xlated_port} session_id=%{INT:session_id} reason=%{GREEDYDATA:reason}
NETSCREENLOG2 %{NETSCREENCOMMONLOG} src_port=%{SRCPORT} dst_port=%{DSTPORT} session_id=%{INT:session_id}"
NETSCREENLOG3 %{NETSCREENCOMMONLOG} icmp .*session_id=%{INT:session_id} reason=%{GREEDYDATA:reason}
```

---

### Simple Config
###### /etc/logstash/conf.d/simple.conf
```
input {
    file {
        path => ["/home/softnixlogger/groups/514/*/*/*/*/*.log"]
        start_position => "beginning"
        sincedb_path => "/dev/null"
    }
}
filter { 
    if [type_log] =~ "netscreen" {
        grok {
            patterns_dir => ["/etc/logstash/patterns"]
            match => [
                "syslog_message", "%{NETSCREENLOG1}",
                "syslog_message", "%{NETSCREENLOG2}",
                "syslog_message", "%{NETSCREENLOG3}"
            ]
        }
    }
}
output { stdout { codec => rubydebug { metadata => true } } }
```

---

# Let's start 
# Basic
# ![](images/elastic-logstash-fw.png)

---

# Logstash::Grok()->input
/root/apache.log
```
83.149.9.216 - - [04/Jan/2015:05:13:42 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
```
/root/simple.conf
```
input {
    file {
        path => "/root/apache.log"
        start_position => "beginning"
        sincedb_path => "/dev/null"
    }
}
```

---
# Logstash::Grok()->filter
```
filter { }
```
# Logstash::Grok()->output
```
output {
    stdout {
        codec => rubydebug {
            metadata => true
        }
    }
}
```

---
# Logstash::Run()
##### Test config
```
/opt/logstash/bin/logstash -f /root/simple.conf --configtest
```

##### Run
```
/opt/logstash/bin/logstash -f /root/simple.conf
```

---
# Logstash::Grok()->print()->Output
```
{
       "message" => "83.149.9.216 - - [04/Jan/2015:05:13:42 +0000] \"GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1\" 200 203023 \"http://semicomplete.com/presentations/logstash-monitorama-2013/\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36\"",
      "@version" => "1",
    "@timestamp" => "2016-09-07T09:37:38.640Z",
          "path" => "/root/apache.log",
          "host" => "0.0.0.0",
     "@metadata" => {
        "path" => "/root/apache.log"
    }
}
```

---

# Logstash::Grok()->addFilter
```
filter {
    grok {
    	match => { "message" => "%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] \"(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})\" %{NUMBER:response} (?:%{NUMBER:bytes}|-) %{QS:referrer} %{QS:agent}"}
    }
}
```
##### Test && Run
```
/opt/logstash/bin/logstash -f /root/simple.conf -t
/opt/logstash/bin/logstash -f /root/simple.conf
```

---
# Logstash::Grok()->print()->Output
```
{
        "message" => "83.149.9.216 - - [04/Jan/2015:05:13:42 +0000] \"GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1\" 200 203023 \"http://semicomplete.com/presentations/logstash-monitorama-2013/\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36\"",
       "@version" => "1",
     "@timestamp" => "2016-09-07T09:41:05.479Z",
           "path" => "/root/apache.log",
           "host" => "0.0.0.0",
       "clientip" => "83.149.9.216",
          "ident" => "-",
           "auth" => "-",
      "timestamp" => "04/Jan/2015:05:13:42 +0000",
           "verb" => "GET",
        "request" => "/presentations/logstash-monitorama-2013/images/kibana-search.png",
    "httpversion" => "1.1",
       "response" => "200",
          "bytes" => "203023",
       "referrer" => "\"http://semicomplete.com/presentations/logstash-monitorama-2013/\"",
          "agent" => "\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36\"",
      "@metadata" => {
        "path" => "/root/apache.log"
    }
}
```

---
# Logstash::Patterns()
```
filter {
    grok {
        match => { "message" => "%{COMBINEDAPACHELOG}"}
    }
}
```
###### Apache pattern is definded
```
COMMONAPACHELOG %{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-)
COMBINEDAPACHELOG %{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}
```
---
# End Basic
# ![](images/elastic-logstash-fw.png)

---
# Q&A

---
# Logstash Grok patterns for Softnix Log Query


