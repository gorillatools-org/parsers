$res = `

place your response here!

`;

if (isset($res)) {
    $d = json_decode($res, true);
    if (isset($d["error"]) && isset($d["error_code"])) {
        die($d["error"]);
    }

    if ($d) {
        foreach ($d as $e) {
            if ($e['module'] === 'emailchecker') {
                echo "~ Email Checker ~<br>";
                foreach ($e['data'] as $i) {
                    echo "- {$i['domain']}<br>";
                }
                echo "<br>";
                break;
            }
        }
        
        foreach ($d as $e) {
            if ($e['module'] !== 'emailchecker') {
                if (strtolower($e['module']) === 'hibp') {
                    echo "~ hibp (HaveIBeenPwned / https://haveibeenpwned.com) ~<br>";
                } else {
                    echo "~ ". ucfirst($e['module']). " ~<br>";
                }
        
                foreach ($e['data'] as $k => $v) {
                    if (is_array($v)) {
                        $e['data'][$k] = array_filter($v, function ($vv) {
                            return !($vv === '' || is_null($vv) || (is_array($vv) && empty($vv)));
                        });
                    } else {
                        if ($v === '' || is_null($v)) {
                            unset($e['data'][$k]);
                        } elseif (strpos($v, 'data:image') !== false) {
                            $e['data'][$k] = '(link too long)';
                        }
                    }
                }
        
                _aI($e['data']);
        
                foreach ($e['front_schemas'] as $s) {
                    echo str_repeat("&nbsp;", 4) . "> [tags] {$s['module']}:<br>";
                    foreach ($s['tags'] as $t) {
                        echo str_repeat("&nbsp;", 8) . "+ {$t['tag']}<br>";
                    }
                    echo "<br>";
                }
        
                echo "<br>";
            }
        }
    } else {
        http_response_code(500);
        $c = explode(" ", $res);
        if (end($c) == 404 && prev($c) == "Code:") {
            echo json_encode(array("error" => "Something messed up while constructing the data. Contact Dev!"));
        } else {
            die($res);
        }
    }
} else {
    http_response_code(400);
    echo json_encode(array("error" => "cannot parse empty or null response", "error_code" => 8));
}

function _aI($a, $l = 0) { // auto tab-indenter
    foreach ($a as $k => $v) {
        if (is_array($v)) {
            if (empty($v)) {
                echo str_repeat("&nbsp;", $l * 4) . "> {$k}: (empty array)<br>";
            } else {
                echo str_repeat("&nbsp;", $l * 4) . "> {$k}:<br>";
                if (array_keys($v) === range(0, count($v) - 1)) {
                    foreach ($v as $i) {
                        if (is_array($i)) {
                            _aI($i, $l + 1);
                        } else {
                            echo str_repeat("&nbsp;", ($l + 1) * 4) . "{$i}<br>";
                        }
                    }
                } else {
                    _aI($v, $l + 1);
                }
            }
        } else {
            echo str_repeat("&nbsp;", $l * 4) . "{$k}: ";
            if (is_bool($v)) {
                echo $v ? 'true' : 'false';
                echo "<br>";
            } elseif (is_string($v)) {
                echo htmlspecialchars(filter_var($v, FILTER_SANITIZE_STRING)) . "<br>"; // basic filtering due to unexpected randomized output from some corrupted api sources.
            } else {
                echo $v . "<br>";
            }
        }
    }
}
