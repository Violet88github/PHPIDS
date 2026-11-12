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

use IDS\Converter;
use IDS\Filter;
use IDS\Init;
use IDS\Monitor;

/**
 * Long and crafted values: they used to hide an attack completely (a failed
 * regular expression emptied the value or counted as "no match") or to keep
 * the scan busy for minutes.
 */
class LargeInputTest extends \PHPUnit\Framework\TestCase
{
    const XSS  = '<script>alert(document.cookie)</script>';
    const SQLI = "1' UNION SELECT username,password FROM users-- ";

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
    private function filterIds(array $request, $name = 'POST.q')
    {
        $report = (new Monitor($this->init))->run($request);
        $event  = $report->getEvent($name);
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

    private function scan($value)
    {
        return $this->filterIds(array('POST' => array('q' => $value)));
    }

    public static function getPaddings()
    {
        return array(
            'slashes'    => array('/ '),
            'commas'     => array(', '),
            'brackets'   => array("(' "),
            'tags'       => array('<a '),
            'tabs'       => array("\t"),
            'entities'   => array('&#x41;'),
            'plain text' => array('lorem ipsum '),
        );
    }

    /**
     * 800 KB of "/ " in front of the payload used to bring the impact to 0.
     *
     * @dataProvider getPaddings
     */
    public function testPaddingInFrontOfAnAttackDoesNotHideIt($padding)
    {
        foreach (array(self::XSS, self::SQLI) as $payload) {
            // what is in front of a payload changes which rules match it, so
            // the comparison is with the same padding in a short value
            $expected = $this->scan(str_repeat($padding, 20) . $payload);
            $this->assertNotEmpty($expected);

            foreach (array(20000, 300000, 1500000) as $bytes) {
                $found = $this->scan(str_repeat($padding, (int) ($bytes / strlen($padding))) . $payload);

                $this->assertNotEmpty($found, "passed as clean behind $bytes bytes of " . json_encode($padding));

                // some paddings are slow to scan: then the value is
                // reported as not fully scanned instead
                if (in_array(Monitor::SCAN_TIME_FILTER_ID, $found, true)) {
                    continue;
                }

                $this->assertSame(
                    array(),
                    array_values(array_diff($expected, $found)),
                    "rules lost behind $bytes bytes of " . json_encode($padding)
                );
            }
        }
    }

    public function testAttackInTheMiddleOfALongValueIsDetected()
    {
        $expected = $this->scan(self::XSS);
        $filler   = str_repeat('lorem ipsum ', 10000);

        $found = $this->scan($filler . self::XSS . $filler);

        $this->assertSame(array(), array_values(array_diff($expected, $found)));
    }

    public function testAttackOnAChunkBorderIsDetected()
    {
        $expected = $this->scan(self::XSS);

        // move the payload byte by byte across the first chunk borders
        foreach (array(3072, 4096, 6144, 8192) as $border) {
            for ($shift = -strlen(self::XSS) - 2; $shift <= 2; $shift += 3) {
                $value = str_repeat('a', $border + $shift) . self::XSS . str_repeat(' lorem', 3000);
                $found = $this->scan($value);

                $this->assertSame(
                    array(),
                    array_values(array_diff($expected, $found)),
                    'payload at byte ' . ($border + $shift)
                );
            }
        }
    }

    public function testMultibyteCharactersAreNotSplit()
    {
        $expected = $this->scan(self::XSS);

        foreach (array(0, 1, 2, 3) as $shift) {
            $found = $this->scan(str_repeat('a', $shift) . str_repeat('日本語', 5000) . self::XSS);

            $this->assertNotContains(Monitor::REGEX_FAILURE_FILTER_ID, $found);
            $this->assertSame(array(), array_values(array_diff($expected, $found)));
        }
    }

    public function testValueOverTheScanLimitIsReported()
    {
        // purely alphanumeric values are never scanned, hence the comma
        $filler = str_repeat('lorem, ipsum ', 100000);

        $found = $this->scan($filler . $filler);

        $this->assertSame(array(Monitor::OVERSIZED_FILTER_ID), $found);
    }

    public function testValueWithinTheScanLimitIsNotReported()
    {
        $this->assertSame(array(), $this->scan(str_repeat('lorem, ipsum ', 30000)));
    }

    public function testScanLimitCountsForTheWholeRequest()
    {
        $filler = str_repeat('lorem, ipsum ', 30000);
        $report = (new Monitor($this->init))->run(
            array('POST' => array('a' => $filler, 'b' => $filler, 'c' => self::XSS))
        );

        $this->assertNull($report->getEvent('POST.a'));
        $this->assertNotNull($report->getEvent('POST.b'));
        $this->assertSame(Monitor::OVERSIZED_FILTER_ID, $report->getEvent('POST.b')->getFilters()[0]->getId());
        // short values are always scanned
        $this->assertNotNull($report->getEvent('POST.c'));
    }

    /**
     * 50 KB of plain HTML paragraphs used to take about 9 seconds, 200 KB of
     * slashes or tabs more than a minute.
     */
    public function testLongValuesAreScannedInReasonableTime()
    {
        $values = array(
            'html'    => str_repeat('<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p> ', 800),
            'slashes' => str_repeat('/ ', 100000),
            'tabs'    => str_repeat("\t", 200000),
        );

        foreach ($values as $name => $value) {
            $start = microtime(true);
            $this->scan($value);

            $this->assertLessThan(5, microtime(true) - $start, "$name took too long");
        }
    }

    public function testScanStopsAtTheTimeLimitAndReportsIt()
    {
        $this->init->config['General']['max_scan_time'] = 0.000001;

        try {
            $monitor = new Monitor($this->init);
        } finally {
            unset($this->init->config['General']['max_scan_time']);
        }

        $report = $monitor->run(
            array('POST' => array('a' => str_repeat('lorem, ipsum ', 30000), 'b' => self::XSS, 'c' => 'harmless'))
        );

        // nothing that could hold an attack is passed as clean
        foreach (array('POST.a', 'POST.b') as $name) {
            $ids = array();
            foreach ($report->getEvent($name)->getFilters() as $filter) {
                $ids[] = $filter->getId();
            }
            $this->assertContains(Monitor::SCAN_TIME_FILTER_ID, $ids);
        }
        $this->assertNull($report->getEvent('POST.c'));
    }

    public function testPlainHtmlIsNotAnAttack()
    {
        $html = str_repeat('<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p> ', 800);

        $this->assertSame(array(), $this->scan($html));
    }

    public function testFilterTellsAFailedMatchFromNoMatch()
    {
        $filter = new Filter(1, '(?:a+)+$', 'catastrophic backtracking', array('test'), 1);

        $this->assertTrue($filter->tryMatch('aaa'));
        $this->assertFalse($filter->tryMatch('b'));

        $this->withTinyPcreLimits(function () use ($filter) {
            $value = str_repeat('a', 64) . 'b';

            $this->assertNull($filter->tryMatch($value));
            $this->assertFalse($filter->match($value));
        });
    }

    public function testFailedRuleIsReported()
    {
        $monitor = new Monitor($this->init);

        $storage = new \ReflectionProperty($monitor, 'storage');
        $storage->setAccessible(true);
        $storage->getValue($monitor)->addFilter(
            new Filter(9999, '(?:a+)+$', 'catastrophic backtracking', array('test'), 1)
        );

        $ids = $this->withTinyPcreLimits(function () use ($monitor) {
            $report = $monitor->run(array('q' => '<' . str_repeat('a', 64) . 'b'));
            $this->assertNotNull($report->getEvent('q'));

            return array_map(
                function (Filter $filter) {
                    return $filter->getId();
                },
                $report->getEvent('q')->getFilters()
            );
        });

        $this->assertContains(Monitor::REGEX_FAILURE_FILTER_ID, $ids);
    }

    /**
     * A failed preg_replace() returns null, which used to turn the value
     * into an empty string for every converter and rule after it.
     */
    public function testFailedConverterKeepsTheValue()
    {
        $value = str_repeat('/ ', 2000) . self::XSS;

        $converted = $this->withTinyPcreLimits(function () use ($value) {
            Converter::resetRegexFailures();

            return Converter::runAll($value);
        });

        $this->assertGreaterThan(0, Converter::getRegexFailures());
        $this->assertStringContainsString('alert', $converted);

        Converter::resetRegexFailures();
        $this->assertSame(0, Converter::getRegexFailures());
    }

    public function testXmlAndJsonRulesAreTheSame()
    {
        $xml  = array();
        $json = array();

        foreach (simplexml_load_file(IDS_FILTER_SET_XML)->filter as $filter) {
            $xml[(string) $filter->id] = array((string) $filter->rule, (int) $filter->impact);
        }
        foreach (json_decode(file_get_contents(IDS_FILTER_SET_JSON))->filters->filter as $filter) {
            $json[(string) $filter->id] = array((string) $filter->rule, (int) $filter->impact);
        }

        $this->assertNotEmpty($xml);
        $this->assertSame($xml, $json);
    }

    /**
     * Runs the callback with PCRE limits so low that a harmless test value
     * exhausts them. The JIT has no backtrack limit, so it is switched off.
     */
    private function withTinyPcreLimits(callable $callback)
    {
        $jit   = ini_set('pcre.jit', '0');
        $limit = ini_set('pcre.backtrack_limit', '50');

        try {
            return $callback();
        } finally {
            ini_set('pcre.backtrack_limit', (string) $limit);
            if ($jit !== false) {
                ini_set('pcre.jit', (string) $jit);
            }
        }
    }
}
