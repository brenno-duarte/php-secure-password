<?php

namespace SecurePassword;

use SecurePassword\Encrypt\Adapter\OpenSslEncryption;
use SecurePassword\Encrypt\Adapter\SodiumEncryption;
use SecurePassword\Encrypt\Encryption;

trait PepperTrait
{
    /**
     * @var string
     */
    private string $pepper;

    /**
     * Create a secret entry (commonly called `pepper`)
     * 
     * @param string $pepper
     * 
     * @return self
     */
    public function setPepper(string $pepper = "default_hash", string $crypt_type = "openssl"): self
    {
        $this->pepper = $pepper;
        $this->pepper = match ($crypt_type) {
            'openssl' => $this->useOpenSSL(),
            'sodium' => $this->useSodium(),
        };

        return $this;
    }

    /**
     * @return string
     */
    public function getPepper(): string
    {
        return $this->pepper;
    }

    /**
     * @return mixed
     */
    private function useOpenSSL(): mixed
    {
        $encryption = new Encryption(new OpenSslEncryption($this->pepper));
        return $encryption->encrypt($this->pepper);
    }

    /**
     * @return mixed
     */
    private function useSodium(): mixed
    {
        $encryption = new Encryption(new SodiumEncryption($this->pepper));
        return $encryption->encrypt($this->pepper);
    }


    /**
     * Adds a secret entry (commonly called `pepper`) to the password 
     * 
     * @param string $password
     * 
     * @return string
     */
    private function passwordPeppered(string $password): string
    {
        return hash_hmac("sha256", $password, $this->getPepper());
    }
}
