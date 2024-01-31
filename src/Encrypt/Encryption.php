<?php

namespace SecurePassword\Encrypt;

use SecurePassword\Encrypt\Adapter\AbstractAdapterInterface;

class Encryption
{
    /**
     * @param AbstractAdapterInterface $adapter
     */
    public function __construct(
        private AbstractAdapterInterface $adapter
    ) {
    }

    /**
     * Encrypt the message.
     *
     * @param mixed $data data to be encrypted
     *
     * @return mixed
     */
    public function encrypt(mixed $data): mixed
    {
        return $this->adapter->encrypt($data);
    }

    /**
     * Decrypt the message.
     *
     * @param mixed $token encrypted token

     * @return mixed
     */
    public function decrypt(mixed $token): mixed
    {
        return $this->adapter->decrypt($token);
    }
}
