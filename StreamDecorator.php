<?php
/**
 * Created by PhpStorm.
 * User: Никита
 * Date: 10.09.2020
 * Time: 15:59
 */

namespace N1kitaG\Psr7;

require_once 'Decorator.php';

use Psr\Http\Message\StreamInterface;
use N1kitaG\Psr7\Decorator;

class StreamDecorator extends Decorator
{


    public function __construct($fileName)
    {
        $this->fileType = substr($fileName, '0', strpos($fileName, '.'));
        $this->resource = self::SAMPLES_DIRECTORY . $this->fileType . self::ORIG_EXTENSION;

        $this->mediaKey     = $this->getMediaKey();
        $this->cryptoArray  = $this->getCryptoArrayValues();

        $this->encryptFile();
    }

    private function encryptFile(): bool
    {
        $this->resourceSidecar = self::SAMPLES_DIRECTORY . $this->fileType . parent::SDC_EXTENSION;

        $fp         = fopen($this->resource, 'r');
        $content    = fread($fp, filesize($this->resource));
        $splitted   = str_split($content, '64000');

        $result     = '';
        foreach ($splitted as $chunk) {
            $enc        = openssl_encrypt($chunk, 'aes-256-cbc', $this->cryptoArray['cipherKey'], OPENSSL_RAW_DATA, $this->cryptoArray['iv']);
            $mac        = substr(hash_hmac($this->algorithm, $this->cryptoArray['iv'] . $enc, $this->cryptoArray['macKey'], true), 0, 10);

            $result    .= $mac;
        }

        $fp = fopen($this->resourceSidecar, 'w+');
        fwrite($fp, $result);
        fclose($fp);

        return true;
    }
}