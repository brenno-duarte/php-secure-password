<?php

namespace SecurePassword\Encrypt\Adapter;

class SodiumEncryption implements AbstractAdapterInterface
{
    /**
     * Store secret key.
     *
     * @var string
     */
    private string $key;

    /**
     * __Construct.
     *
     * @param string $key
     */
    public function __construct(string $key)
    {
        if ($key === '') {
            throw new \InvalidArgumentException('The key should not be empty string.');
        }
        
        if (!function_exists('sodium_crypto_secretbox_keygen')) {
            throw new \Exception('The sodium php extension does not installed or enabled', 500);
        }

        //should use user define key.
        $this->key = substr(hash('sha512', $key), 0, 32);
    }

    /**
     * Encrypt the message.
     *
     * @param string $data data to be encrypted
     * 
     * @return mixed
     */
    public function encrypt(mixed $data): mixed
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $token = base64_encode($nonce.sodium_crypto_secretbox($data, $nonce, $this->key).'&&'.$this->key);

        return $token;
    }

    /**
     * Decrypt the message.
     *
     * @param mixed $token encrypted token

     * @return mixed
     */
    public function decrypt(mixed $token): mixed
    {
        $decoded = base64_decode($token);
        list($decoded, $this->key) = explode('&&', $decoded);
        
        if ($decoded === false) {
            throw new \Exception('The decoding failed');
        }

        if (mb_strlen($decoded, '8bit') < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) {
            throw new \Exception('The token was truncated');
        }

        $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $ciphertext = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

        $plain = sodium_crypto_secretbox_open($ciphertext,
        $nonce, $this->key);

        if ($plain === false) {
            throw new \Exception('The message was tampered with in transit');
        }

        return $plain;
    }
}
