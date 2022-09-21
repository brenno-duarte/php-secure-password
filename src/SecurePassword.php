<?php

namespace SecurePassword;

use SecurePassword\HashAlgorithm;
use SecurePassword\HashException;

class SecurePassword extends HashAlgorithm
{
    /**
     * @var string
     */
    private string $pepper;

    /**
     * @var string
     */
    private string $pwd_hashed = "";

    /**
     * @var string
     */
    private string $password = "";

    /**
     * @var array
     */
    private array $config = [
        "algo" => self::DEFAULT,
        "cost" => "",
        "memory_cost" => "",
        "time_cost" => "",
        "threads" => ""
    ];

    /**
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        if (!empty($config)) {
            foreach ($config as $key => $value) {
                if (!isset($this->config[$key])) {
                    throw new HashException("Key '$key' not exists");
                } else {
                    $this->options = $config;
                    $this->algo = $this->options['algo'];
                }
            }
        } else {
            if (empty($this->algo)) {
                $this->algo = self::DEFAULT;
            }
        }

        $this->setPepper();
    }

    /**
     * Create a secret entry (commonly called `pepper`)
     * 
     * @param string $pepper
     * 
     * @return SecurePassword
     */
    public function setPepper(string $pepper = "default_hash"): SecurePassword
    {
        $this->pepper = $this->createPepper($pepper);

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
     * Creates a password peppered using the entered password and the secret entry. 
     * 
     * @param string $password
     * 
     * @return SecurePassword
     */
    public function createHash(string $password): SecurePassword
    {
        $this->password = $password;

        $pwd_peppered = $this->passwordPeppered($this->password);
        $this->pwd_hashed = password_hash($pwd_peppered, $this->algo, $this->options);

        return $this;
    }

    /**
     * @return string
     */
    public function getHash(): string
    {
        return $this->pwd_hashed;
    }

    /**
     * @return array
     */
    public function getHashInfo(): array
    {
        return password_get_info($this->pwd_hashed);
    }

    /**
     * Verify if the hash generated with `createHash` is valid
     * 
     * @param null|string $password
     * @param null|string $hash
     * 
     * @return mixed
     */
    public function verifyHash(?string $password = null, ?string $hash = null): mixed
    {
        if (is_null($password) && $this->password != "") {
            $password = $this->password;
        }

        if (is_null($hash) && $this->pwd_hashed != "") {
            $hash = $this->pwd_hashed;
        }

        $pph_strt = microtime(true);
        $pwd_peppered = $this->passwordPeppered($password);

        if (password_verify($pwd_peppered, $hash)) {
            try {
                return true;
            } finally {
                $end = (microtime(true) - $pph_strt);
                $wait = bcmul((1 - $end), 1000000);  // usleep(250000) 1/4 of a second
                usleep($wait);
            }
        } else {
            return false;
        }
    }

    /**
     * Here's a quick little function that will help you determine what cost parameter you should be 
     * using for your server to make sure you are within this range.
     * 
     * @param int $min_ms
     * @param string $password
     * 
     * @return int
     */
    public function getOptimalBcryptCost(int $min_ms = 250, string $password = "test"): int
    {
        for ($i = 4; $i < 31; $i++) {
            $time_start = microtime(true);
            password_hash($password, PASSWORD_BCRYPT, ['cost' => $i]);
            $time_end = microtime(true);

            if (($time_end - $time_start) * 1000 > $min_ms) {
                return $i;
            }
        }
    }

    /**
     * This function checks to see if the supplied hash implements the algorithm and options provided. 
     * If not, it is assumed that the hash needs to be rehashed.
     * 
     * @param string $password
     * @param string $hash
     * 
     * @return mixed
     */
    public function needsRehash(string $password, string $hash): mixed
    {
        if (password_needs_rehash($hash, $this->algo)) {
            $newHash = $this->createHash($password)->getHash();

            return $newHash;
        } else {
            return false;
        }
    }

    /**
     * @param string $pepper
     * 
     * @return string
     */
    private function createPepper(string $pepper): string
    {
        return openssl_encrypt($pepper, "AES-128-CBC", pack('a16', 'secure_password_1'), 0, pack('a16', 'secure_password_2'));
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
