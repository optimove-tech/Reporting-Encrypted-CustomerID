<?php
$hmacBytesLen = 32;
$ivByteLen=16;
$algo = 'aes-256-cbc';

function encrypt($message, $key) {

    $iv = openssl_random_pseudo_bytes($GLOBALS['ivByteLen']);
    $iv64 = base64_encode($iv);
    $hmacAlgo = 'sha256';

    $encrypted64 = openssl_encrypt($message, $GLOBALS['algo'], $key,0, $iv);
    $encrypted = base64_decode($encrypted64);
    $ivEncrypted = $iv.$encrypted;
    $hmac = hash_hmac($hmacAlgo, $ivEncrypted,  $key, true);
    $finalEncrypted = $iv.$encrypted.$hmac;
    $finalEncrypted64 = base64_encode($finalEncrypted);

    return $finalEncrypted64;
}

function decrypt($encrypted64, $key){
    echo nl2br ("\n");
    $encrypted = base64_decode($encrypted64);
    $len = strlen($encrypted);
    $subEncrypted = substr($encrypted, 0, $len - $GLOBALS['hmacBytesLen'] );
    $iv = substr($subEncrypted, 0,  $GLOBALS['ivByteLen']  );
    $subEncrypted = substr($subEncrypted, $GLOBALS['ivByteLen'] , $len - $GLOBALS['hmacBytesLen'] - $GLOBALS['ivByteLen']  );
    $subEncrypted64 = base64_encode($subEncrypted);
    $decrypted = openssl_decrypt($subEncrypted64, $GLOBALS['algo'], $key, 0 ,$iv);
    echo nl2br ("decrypted: ".$decrypted." \n");
}


$key = "DH6asttV1CL2yp6YaXPimFSHc9BM3xiw";
$data = "secret message";

echo nl2br ("original: ".$data." \n");

$ciphertext = encrypt($data, $key);
$decrypted = decrypt($ciphertext, $key);

?>