<?php

require_once 'php-ecrecover/CryptoCurrencyPHP/PointMathGMP.class.php';
require_once 'php-ecrecover/CryptoCurrencyPHP/SECp256k1.class.php';
require_once 'php-ecrecover/CryptoCurrencyPHP/Signature.class.php';
require_once 'php-ecrecover/vendor/autoload.php';
use kornrunner\Keccak;


class Web3Tools {

  // https://eth.wiki/json-rpc/API
  
  public $jsonrpc_url = 'https://rinkeby-light.eth.linkpool.io';
  public $network = 4;
  public $contract = '0x4c75c69156c97d5f606553fcefa55e98e6f85020';

   public function __construct ($rpc = null, $network = null, $contract = null) {
     if ($rpc) $this->jsonrpc_url = $rpc;
     if ($network) $this->network = $network;
     if ($contract) $this->contract = $contract;
   }

   public function validateSignedRequest($address, $message, $signature) {
    if (strtolower($address) == $this->personal_ecRecover($message, $signature)) {
      return true;
    }    
    return false;
   }

   public function getCurrentBlock() {
    $request = $this->buildRpcRequest('eth_blockNumber', false, false);
    $response = $this->makeRpcRequest($request);
    if ($response) {
      return $response->result;
    }
    return false;
   }

   public function getNftOwner($number) {
    $params = new stdClass;
    $params->to = $this->contract;
    $params->data = sprintf('0x6352211e%064x', $number);
    $request = $this->buildRpcRequest('eth_call', $params);
    $response = $this->makeRpcRequest($request);

    if ($response && $response->result) {
      $address = substr($response->result, 26);
      return $address;
    }
    return false;
   }

   public function getNftUri() {
    $params = new stdClass;
    $params->to = $this->contract;
    $params->data = '0xc87b56dd0000000000000000000000000000000000000000000000000000000000000001';
    $request = $this->buildRpcRequest('eth_call', $params);
    $response = $this->makeRpcRequest($request);

    if ($response && $response->result) {
      $length = hexdec(substr($response->result, 66, 64));
      $uri = hex2bin(substr($response->result, 130, ($length * 2)));
      $this->d($uri);
      return $uri;
    }
    return '';
   }

   public function buildRpcRequest($method, $params = false, $version = 'latest') {
     $request = new stdClass;
     $request->id = '1';
     $request->jsonrpc = '2.0';
     $request->method = $method;
     if ($params) {
      if ($version) {
        $request->params = [$params, $version];
      } else {
        $request->params = [$params];
      }
     }
     return $request;
   }
   
   public function makeRpcRequest($request) {
     $ch = curl_init();
      curl_setopt($ch, CURLOPT_URL, $this->jsonrpc_url);
      curl_setopt($ch, CURLOPT_POST, 1);
      curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($request));
      curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
     $response = curl_exec($ch);
     curl_close($ch);
     if ($response) {
       return json_decode($response);
     }
     return false;
   }

   public function personal_ecRecover($msg, $signed) {
    $personal_prefix_msg = "\x19Ethereum Signed Message:\n". strlen($msg). $msg;
    $hex = $this->keccak256($personal_prefix_msg);
    return $this->ecRecover($hex, $signed);
   }

   public function ecRecover($hex, $signed) {
    $rHex   = substr($signed, 2, 64);
    $sHex   = substr($signed, 66, 64);
    $vValue = hexdec(substr($signed, 130, 2));
    $messageHex       = substr($hex, 2);
    $messageByteArray = unpack('C*', hex2bin($messageHex));
    $messageGmp       = gmp_init("0x" . $messageHex);
    $r = $rHex;		//hex string without 0x
    $s = $sHex; 	//hex string without 0x
    $v = $vValue; 	//27 or 28

    //with hex2bin it gives the same byte array as the javascript
    $rByteArray = unpack('C*', hex2bin($r));
    $sByteArray = unpack('C*', hex2bin($s));
    $rGmp = gmp_init("0x" . $r);
    $sGmp = gmp_init("0x" . $s);

    $recovery = $v - 27;
    if ($recovery !== 0 && $recovery !== 1) {
        throw new Exception('Invalid signature v value');
    }

    $publicKey = Signature::recoverPublicKey($rGmp, $sGmp, $messageGmp, $recovery);
    $publicKeyString = $publicKey["x"] . $publicKey["y"];

    return '0x'. substr($this->keccak256(hex2bin($publicKeyString)), -40);
  }

  public function strToHex($string) {
      $hex = unpack('H*', $string);
      return '0x' . array_shift($hex);
  }

  public function keccak256($str) {
      return '0x'. Keccak::hash($str, 256);
  }
  
  public function d ( $var ) {
    echo '<pre style="color: red;">';
    var_dump( $var );
    echo '</pre>';
  }

}
