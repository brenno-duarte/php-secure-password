<?php

namespace SecurePassword\Encrypt\Adapter;

class OpenSslEncryption implements AbstractAdapterInterface
{
    /**
     * Store the cipher iv.
     *
     * @var string
     */
    private string $iv;

    /**
     * Store secret key.
     *
     * @var string
     */
    private string $key;

    /**
     * Cipher.
     *
     * @var string
     */
    private string $cipher = 'AES-256-CBC';

    /**
     * __Construct.
     *
     * @since 1.0.0
     *
     * @return void
     */
    public function __construct(string $key)
    {
        if ($key === '') throw new \InvalidArgumentException('The key should not be empty string.');
        $this->iv = openssl_random_pseudo_bytes($this->ivBytes($this->cipher));
        $this->key = hash('sha512', $key);
    }

    /**
     * Encrypt the message.
     *
     * @param mixed $data => data to be encrypted
     *
     * @return mixed
     */
    public function encrypt(mixed $data): mixed
    {
        return base64_encode(
            openssl_encrypt($data, $this->cipher, $this->key, 0, $this->iv) . '&&' . bin2hex($this->iv)
        );
    }

    /**
     * Decrypt the message.
     *
     * @param mixed $token => encrypted token

     * @return string|bool
     */
    public function decrypt(mixed $token): string|bool
    {
        $token = base64_decode($token);
        list($token, $this->iv) = explode('&&', $token);
        return openssl_decrypt($token, $this->cipher, $this->key, 0, hex2bin($this->iv));
    }

    /**
     * Get the length of cipher.
     *
     * @param $method

     * @return int
     */
    protected function ivBytes(string $method): int
    {
        return openssl_cipher_iv_length($method);
    }
}
