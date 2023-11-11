<?php

namespace Lablnet\Tests;

use InvalidArgumentException;
use SecurePassword\Encrypt\Adapter\OpenSslEncryption;
use SecurePassword\Encrypt\Adapter\SodiumEncryption;
use SecurePassword\Encrypt\Encryption;
use PHPUnit\Framework\TestCase;

class EncryptionTest extends TestCase
{
    public function testEncryptAndDecryptOnDifferentKeyWithOpenSsl()
    {
        $encryption = new Encryption(new OpenSslEncryption('12345678990-=====-==='));
        $encryptedString = $encryption->encrypt('plain-text');

        $encryption2 = new Encryption(new OpenSslEncryption('different_key'));
        $decryptedString = $encryption2->decrypt($encryptedString);

        $this->assertFalse($decryptedString);
    }

    public function testEncryptAndDecryptWithOpenSsl()
    {
        $encryption = new Encryption(new OpenSslEncryption('12345678990-=====-==='));
        $encryptedString = $encryption->encrypt('plain-text');
        $decryptedString = $encryption->decrypt($encryptedString);

        $this->assertStringEndsWith('==', $encryptedString);
        $this->assertSame(80, strlen($encryptedString));
        $this->assertSame('plain-text', $decryptedString);
    }

    public function testEncryptAndDecryptWithSodium()
    {
        $encryption = new Encryption(new SodiumEncryption('euyq74tjfdskjFDSGq74'));
        $encryptedString = $encryption->encrypt('plain-text');
        $decryptedString = $encryption->decrypt($encryptedString);

        $this->assertStringEndsNotWith('==', $encryptedString);
        $this->assertSame(112, strlen($encryptedString));
        $this->assertSame('plain-text', $decryptedString);
    }

    public function testOpenSslEncrpytionEncryptOnEmptyStringKey()
    {
        $this->expectException(InvalidArgumentException::class);

        new Encryption(new OpenSslEncryption(''));
    }

    public function testSodiumEncrpytionEncryptOnEmptyStringKey()
    {
        $this->expectException(InvalidArgumentException::class);

        new Encryption(new SodiumEncryption(''));
    }
}
