; <?php die(); ?>

; PHPIDS Config.ini

; General configuration settings

[General]

    ; basic settings - customize to make the PHPIDS work at all
    filter_type     = xml

    base_path       = /full/path/to/IDS/
    use_base_path   = false

    filter_path     = default_filter.xml
    tmp_path        = tmp
    scan_keys       = false

    ; Long values are scanned in overlapping chunks, because the rules are
    ; written for short input: on a long value some of them take very long or
    ; fail, which stalls the request or hides an attack. Sizes are in bytes.
    ;scan_chunk_size    = 4096
    ;scan_chunk_overlap = 1024

    ; Most bytes of long values scanned per request. Of a value that no
    ; longer fits, only the start and the end are scanned, and it is
    ; reported with filter 9002.
    ;max_scan_length    = 524288

    ; Seconds one request may spend in the scan, 0 for no limit. Values that
    ; are not scanned in time are reported with filter 9003. How long a scan
    ; takes depends heavily on pcre.jit: keep it enabled.
    ;max_scan_time      = 2

    ; in case you want to use a different HTMLPurifier source, specify it here
    ; By default, those files are used that are being shipped with PHPIDS
    HTML_Purifier_Cache = vendors/htmlpurifier/HTMLPurifier/DefinitionCache/Serializer

    ; define which fields contain html and need preparation before
    ; hitting the PHPIDS rules (new in PHPIDS 0.5)
    ;html[]          = POST.__wysiwyg

    ; define which fields contain JSON data and should be treated as such
    ; for fewer false positives (new in PHPIDS 0.5.3)
    ;json[]          = POST.__jsondata

    ; define which fields shouldn't be monitored (a[b]=c should be referenced via a.b)
    exceptions[]    = GET.__utmz
    exceptions[]    = GET.__utmc

    ; you can use regular expressions for wildcard exceptions - example: /.*foo/i

[Caching]

    ; caching:      session|file|database|memcached|apc|none
    caching         = file
    expiration_time = 600

    ; file cache
    path            = tmp/default_filter.cache

    ; database cache
    wrapper         = "mysql:host=localhost;port=3306;dbname=phpids"
    user            = phpids_user
    password        = 123456
    table           = cache

    ; memcached
    ;host           = localhost
    ;port           = 11211
    ;key_prefix     = PHPIDS

    ; apc
    ;key_prefix     = PHPIDS
