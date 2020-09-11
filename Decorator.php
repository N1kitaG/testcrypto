<?php
/**
 * Created by PhpStorm.
 * User: Никита
 * Date: 10.09.2020
 * Time: 14:48
 */
namespace N1kitaG\Psr7;

use Psr\Http\Message\StreamInterface;
use Exception;

abstract class Decorator implements StreamInterface
{
    const IMAGE_CONSTANT    = 'WhatsApp Image Keys';
    const AUDIO_CONSTANT    = 'WhatsApp Video Keys';
    const VIDEO_CONSTANT    = 'WhatsApp Audio Keys';
    const DOCUMENT_CONSTANT = 'WhatsApp Document Keys';
    const HKDF_LENGTH       = 112;
    const SAMPLES_DIRECTORY = './samples/';
    const KEY_EXTENSION     = '.key';
    const ENC_EXTENSION     = '.encrypted';
    const ORIG_EXTENSION    = '.original';
    const SDC_EXTENSION     = '.sidecar';

    /** @var StreamInterface[] Streams being decorated */
    protected $streams = [];

    /** @var bool */
    private $seekable = true;

    /** @var int */
    private $current = 0;

    /** @var int */
    private $pos = 0;

    /** @var string */
    protected $algorithm = 'sha256';

    /** @var string */
    protected $mediaKey;

    /** @var string */
    protected $mac;

    /** @var string */
    protected $enc;

    /** @var string */
    protected $resource;

    /** @var string */
    protected $resourceKey;

    /** @var string */
    protected $resourceEncrypted;

    /** @var string */
    protected $resourceSidecar;

    /** @var array */
    protected $cryptoArray = [
        'iv',
        'cipherKey',
        'macKey'
    ];

    /** @var string */
    protected $fileType;

    protected function getMediaKey() : string
    {
        $this->resourceKey = self::SAMPLES_DIRECTORY . $this->fileType . self::KEY_EXTENSION;

        return (file_exists($this->resourceKey)) ?
            $this->readMediaKeyFile()  :
            $this->createMediaKeyFile();
    }

    protected function createMediaKeyFile(): string
    {
        $handler = fopen($this->resourceKey, 'w+');

        try {
            $this->mediaKey   = random_bytes(32);
        } catch (Exception $exception) {
            echo $exception;
        }

        fwrite($handler, $this->mediaKey);
        fclose($handler);

        return $this->mediaKey;
    }

    protected function readMediaKeyFile(): string
    {
        $handler          = fopen($this->resourceKey, 'r');
        $this->mediaKey   = fread($handler, filesize($this->resourceKey));
        fclose($handler);

        return $this->mediaKey;
    }

    protected function getCryptoArrayValues(): array
    {
        $mediaKeyExpanded   = hash_hkdf($this->algorithm, $this->mediaKey, self::HKDF_LENGTH, self::getInfoHKDF());
        $result             = str_split($mediaKeyExpanded, '16');

        return [
            'iv'        => $result[0],
            'cipherKey' => $result[1] . $result[2],
            'macKey'    => $result[3]
        ];
    }

    protected function getInfoHKDF(): string
    {
        switch ($this->fileType) {
            case 'AUDIO':
                return self::AUDIO_CONSTANT;
            case 'VIDEO':
                return self::VIDEO_CONSTANT;
            case 'IMAGE':
                return self::IMAGE_CONSTANT;
            default:
                return self::DOCUMENT_CONSTANT;
        }
    }


    /**
     * Closes each attached stream.
     */
    public function close(): void
    {
        $this->pos = $this->current = 0;
        $this->seekable = true;

        foreach ($this->streams as $stream) {
            $stream->close();
        }

        $this->streams = [];
    }

    /**
     * Detaches each attached stream.
     *
     * Returns null as it's not clear which underlying stream resource to return.
     */
    public function detach()
    {
        $this->pos = $this->current = 0;
        $this->seekable = true;

        foreach ($this->streams as $stream) {
            $stream->detach();
        }

        $this->streams = [];

        return null;
    }

    public function tell(): int
    {
        return $this->pos;
    }

    public function __toString(): string
    {
        try {
            $this->rewind();
            return $this->getContents();
        } catch (\Throwable $e) {
            if (\PHP_VERSION_ID >= 70400) {
                throw $e;
            }
            trigger_error(sprintf('%s::__toString exception: %s', self::class, (string) $e), E_USER_ERROR);
            return '';
        }
    }

    public function getContents(): string
    {
        return strval($this);
    }

    /**
     * Tries to calculate the size by adding the size of each stream.
     *
     * If any of the streams do not return a valid number, then the size of the
     * append stream cannot be determined and null is returned.
     */
    public function getSize(): ?int
    {
        $size = 0;

        foreach ($this->streams as $stream) {
            $s = $stream->getSize();
            if ($s === null) {
                return null;
            }
            $size += $s;
        }

        return $size;
    }

    public function eof(): bool
    {
        return !$this->streams ||
            ($this->current >= count($this->streams) - 1 &&
                $this->streams[$this->current]->eof());
    }

    public function rewind(): void
    {
        $this->seek(0);
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function isWritable(): bool
    {
        return true;
    }

    public function isSeekable(): bool
    {
        return $this->seekable;
    }

    /**
     * Attempts to seek to the given position. Only supports SEEK_SET.
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        if (!$this->seekable) {
            throw new \RuntimeException('This AppendStream is not seekable');
        } elseif ($whence !== SEEK_SET) {
            throw new \RuntimeException('The AppendStream can only seek with SEEK_SET');
        }

        $this->pos = $this->current = 0;

        // Rewind each stream
        foreach ($this->streams as $i => $stream) {
            try {
                $stream->rewind();
            } catch (\Exception $e) {
                throw new \RuntimeException('Unable to seek stream '
                    . $i . ' of the AppendStream', 0, $e);
            }
        }

        // Seek to the actual position by reading from each stream
        while ($this->pos < $offset && !$this->eof()) {
            $result = $this->read(min(8096, $offset - $this->pos));
            if ($result === '') {
                break;
            }
        }
    }

    /**
     * Reads from all of the appended streams until the length is met or EOF.
     */
    public function read($length): string
    {
        $buffer = '';
        $total = count($this->streams) - 1;
        $remaining = $length;
        $progressToNext = false;

        while ($remaining > 0) {

            // Progress to the next stream if needed.
            if ($progressToNext || $this->streams[$this->current]->eof()) {
                $progressToNext = false;
                if ($this->current === $total) {
                    break;
                }
                $this->current++;
            }

            $result = $this->streams[$this->current]->read($remaining);

            if ($result === '') {
                $progressToNext = true;
                continue;
            }

            $buffer .= $result;
            $remaining = $length - strlen($buffer);
        }

        $this->pos += strlen($buffer);

        return $buffer;
    }

    public function write($string): int
    {
        throw new \RuntimeException('Cannot write to an AppendStream');
    }

    public function getMetadata($key = null)
    {
        return $key ? null : [];
    }

}