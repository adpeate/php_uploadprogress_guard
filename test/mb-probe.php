<?php
header('Content-Type: text/plain');
echo "code=", http_response_code(), " post=", count($_POST), " files=", count($_FILES),
	" v=", isset($_POST['v']) ? bin2hex($_POST['v']) : '-',
	" translation=", ini_get('mbstring.encoding_translation'), " guard=", (int) extension_loaded('hp_uploadprogress_guard'), "\n";
