<?php

namespace N1kitaG\Psr7;

require_once 'Decorator.php';

use Psr\Http\Message\StreamInterface;
use N1kitaG\Psr7\Decorator;

class EncryptionDecorator extends Decorator
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
        $this->resourceEncrypted = self::SAMPLES_DIRECTORY . $this->fileType . self::ENC_EXTENSION;

        // Lets open main file
        $handler    = fopen($this->resource, 'r');
        $content    = fread($handler, filesize($this->resource));
        fclose($handler);

        // Lets Encrypt it
        $this->enc        = openssl_encrypt($content, 'aes-256-cbc', $this->cryptoArray['cipherKey'], OPENSSL_RAW_DATA, $this->cryptoArray['iv']);
        $this->mac        = substr(hash_hmac($this->algorithm, $this->cryptoArray['iv'] . $this->enc, $this->cryptoArray['macKey'], true), 0, 10);

        // Save the result
        $handler          = fopen($this->resourceEncrypted, 'w+');
        fwrite($handler, $this->enc . $this->mac);
        fclose($handler);

        return true;
    }
}