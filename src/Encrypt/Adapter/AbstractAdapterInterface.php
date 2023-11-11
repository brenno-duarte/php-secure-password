<?php

namespace SecurePassword\Encrypt\Adapter;

interface AbstractAdapterInterface
{
    /**
     * Encrypt the message.
     *
     * @param mixed $data data to be encrypted

     * @return mixed
     */
    public function encrypt(mixed $data): mixed;

    /**
     * Decrypt the message.
     *
     * @param mixed $token encrypted token

     * @return mixed
     */
    public function decrypt(mixed $token): mixed;
}
