<?php

use PHPUnit\Framework\TestCase;
use SecurePassword\HashAlgorithm;
use SecurePassword\SecurePassword;

class SecurePasswordTest extends TestCase
{
    public function testCreateHash()
    {
        $password = new SecurePassword();
        $hash = $password->createHash('my_password')->getHash();

        $this->assertIsString($hash);
    }

    public function testCreateHashWithConfig()
    {
        $config = [
            'algo' => HashAlgorithm::ARGON2I,
            'cost' => 10,
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads' => PASSWORD_ARGON2_DEFAULT_THREADS
        ];
        
        $password = new SecurePassword($config);
        $hash = $password->createHash('my_password')->getHash();

        $this->assertIsString($hash);
    }

    public function testChangePepper()
    {
        $password = new SecurePassword();
        $password->setPepper('new_pepper', 'openssl');
        $hash = $password->createHash('my_password')->getHash();

        $this->assertIsString($hash);

        $password->setPepper('new_other_pepper', 'sodium');
        $hash = $password->createHash('my_password')->getHash();

        $this->assertIsString($hash);
    }

    public function testChangeHashAlgorithm()
    {
        $password = new SecurePassword([
            'algo' => HashAlgorithm::ARGON2I
        ]);
        $hash = $password->createHash('my_password')->getHash();

        $this->assertIsString($hash);
    }

    public function testCreateWithAlgorithm()
    {
        $password = new SecurePassword();
        $hash = $password->useArgon2()->createHash('my_password')->getHash();
        $res = $password->useArgon2()->verifyHash('my_password', $hash);

        $this->assertTrue($res);
    }

    public function testCreateWithOtherAlgorithm()
    {
        $password = new SecurePassword();
        $hash = $password->useArgon2()->createHash('my_password')->getHash();
        $needs = $password->useDefault()->needsRehash('my_password', $hash);

        $this->assertIsString($needs);
    }

    public function testHashInfo()
    {
        $password = new SecurePassword();
        $hash = $password->createHash('my_password')->getHashInfo();

        $this->assertIsArray($hash);
    }

    public function testCreateAndVerifyHashChained()
    {
        $password = new SecurePassword();
        $hash = $password->createHash('my_password')->verifyHash();

        $this->assertTrue($hash);
    }

    public function testCreateAndVerifyHash()
    {
        $password = new SecurePassword();
        $hash = $password->createHash('my_password')->getHash();
        $res = $password->verifyHash('my_password', $hash);

        $this->assertTrue($res);
    }

    public function testVerifyHash()
    {
        $hash = '$2y$10$Er0wYRuY7LTYkmWmL8YMMeuxiRIEZ7Vn/8kPb4.aNkzIFRN/N.qG.';
        $res = (new SecurePassword())->verifyHash('my_password', $hash);

        $this->assertTrue($res);

        $password = new SecurePassword();
        $res = $password->createHash('my_password')->verifyHash();

        $this->assertTrue($res);
    }

    public function testVerifyHashWrong()
    {
        $hash = '$2y$10$Er0wYRuY7LTYkmWmL8YMMeuxiRIEZ7Vn/8kPb4.aNkzIFRN/N.qG.';
        $res = (new SecurePassword)->verifyHash('mypassword', $hash);

        $this->assertFalse($res);
    }

    public function testVerifyRehash()
    {
        $hash = '$2y$10$Er0wYRuY7LTYkmWmL8YMMeuxiRIEZ7Vn/8kPb4.aNkzIFRN/N.qG.';
        $res = (new SecurePassword)->useArgon2()->needsRehash('mypassword', $hash);

        $this->assertIsString($res);
    }

    public function testOptimalBcryptCost()
    {
        $res = (new SecurePassword)->getOptimalBcryptCost();

        $this->assertIsInt($res);
    }
}
