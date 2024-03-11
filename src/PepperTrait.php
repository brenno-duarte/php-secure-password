<?php

namespace SecurePassword;

use SecurePassword\Encrypt\Encryption;
use SecurePassword\Encrypt\Adapter\{OpenSslEncryption, SodiumEncryption};

trait PepperTrait
{
    /**
     * @var string
     */
    private string $pepper;

    /**
     * @var string
     */
    private string $crypt_type;

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
        $this->crypt_type = $crypt_type;

        $this->pepper = match ($this->crypt_type) {
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
        if ($this->pepper !== '') {
            if ($this->crypt_type == 'openssl') {
                $encryption = new Encryption(new OpenSslEncryption($this->pepper));
                $this->pepper = $encryption->decrypt($this->pepper);
            }

            if ($this->crypt_type == 'sodium') {
                $encryption = new Encryption(new SodiumEncryption($this->pepper));
                $this->pepper = $encryption->decrypt($this->pepper);
            }
        }

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
    private function passwordPeppered(#[\SensitiveParameter] string $password): string
    {
        return hash_hmac("sha256", $password, $this->getPepper());
    }
}
