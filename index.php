<?php
/**
 * Created by PhpStorm.
 * User: Никита
 * Date: 10.09.2020
 * Time: 13:35
 */

require_once 'EncryptionDecorator.php';
require_once 'DecryptionDecorator.php';
require_once 'StreamDecorator.php';

use N1kitaG\Psr7\EncryptionDecorator;
use N1kitaG\Psr7\DecryptionDecorator;
use N1kitaG\Psr7\StreamDecorator;

$image  = new EncryptionDecorator('IMAGE.original');
$image  = new DecryptionDecorator('IMAGE.original');
$obj    = new StreamDecorator('VIDEO.original');