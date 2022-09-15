# Web3ToolsPHP
PHP Web3 Tools 

## WORK IN PROGRESS

```
require_once('Web3Tools.php');

$w3t = new Web3Tools(
    '0x4c75c69156c97d5f606553fcefa55e98e6f85020', // CONTRACT ADDRESS
    'https://rinkeby-light.eth.linkpool.io', // RPC URL
    4 // NETWORK ID    
);

$tokenURI = $w3t->getNftUri(); // RETURNS TOKEN URI FOR 1ST TOKEN OF SPECIFICED CONTRACT
$metadata = json_decode(file_get_contents($tokenURI)); // GET TOKEN METADATA
```