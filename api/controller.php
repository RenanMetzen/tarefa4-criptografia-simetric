<?php
include('Crypt/RSA.php');

if(isset($_POST['chaves'])){
  $arrayChaves = array();
  $rsa = new Crypt_RSA();
  extract($rsa->createKey());

  $arrayChaves = [$privatekey, $publickey];
  echo json_encode($arrayChaves);
}elseif(isset($_FILES['texto'])){
  $arrayEncrypt = array();
  define('CRYPT_RSA_PKCS15_COMPAT', true);
  ini_set( 'default_charset', 'utf-8');

  $formatosPermitidos = "txt";
  $extensao = pathinfo($_FILES['texto']['name'], PATHINFO_EXTENSION);
  $temporario = $_FILES['texto']['tmp_name'];
  $textoClaro = file_get_contents($temporario);
  str_replace('\r\n', "", $textoClaro);

  $formatosPermitidos = "txt";
  $extensao = pathinfo($_FILES['inputChavePublica']['name'], PATHINFO_EXTENSION);
  $temporario = $_FILES['inputChavePublica']['tmp_name'];
  $chavePublica = file_get_contents($temporario);

  $cipher = "AES-128-CBC";
  $iv = random_bytes(16);
  $key = random_bytes(16);

  $textoCifrado = openssl_encrypt($textoClaro, $cipher, $key, $options=0, $iv);
  
  $iv = bin2hex($iv);
  $key = bin2hex($key);

  // $rsa = new Crypt_RSA();
  // $rsa->loadKey($chavePublica); // public key

  // $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
  // $ciphertext = $rsa->encrypt($textoCifrado);

  $arrayEncrypt = [$textoCifrado, $key, $iv];

  echo json_encode($arrayEncrypt);

}else{
  $arrayEncrypt = array();
  define('CRYPT_RSA_PKCS15_COMPAT', true);
  ini_set( 'default_charset', 'utf-8');

  $formatosPermitidos = "txt";
  $extensao = pathinfo($_FILES['inputTextoCifrado']['name'], PATHINFO_EXTENSION);
  $temporario = $_FILES['inputTextoCifrado']['tmp_name'];
  $textoCifrado = file_get_contents($temporario);

  $formatosPermitidos = "txt";
  $extensao = pathinfo($_FILES['key']['name'], PATHINFO_EXTENSION);
  $temporario = $_FILES['key']['tmp_name'];
  $key = file_get_contents($temporario);
  $key = hex2bin($key);

  $formatosPermitidos = "txt";
  $extensao = pathinfo($_FILES['iv']['name'], PATHINFO_EXTENSION);
  $temporario = $_FILES['iv']['tmp_name'];
  $iv = file_get_contents($temporario);
  $iv = hex2bin($iv);

  $formatosPermitidos = "txt";
  $extensao = pathinfo($_FILES['inputChavePrivada']['name'], PATHINFO_EXTENSION);
  $temporario = $_FILES['inputChavePrivada']['tmp_name'];
  $chavePrivada = file_get_contents($temporario);
  $cipher = "AES-128-CBC";

  $textoClaroOriginal = openssl_decrypt($textoCifrado, $cipher, $key, $options=0, $iv);

  echo json_encode($textoClaroOriginal);
}
?>

