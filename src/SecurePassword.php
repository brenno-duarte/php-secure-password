<?php

namespace SecurePassword;

use SecurePassword\PepperTrait;
use SecurePassword\HashAlgorithm;
use SecurePassword\HashException;

class SecurePassword extends HashAlgorithm
{
    use PepperTrait;

    /**
     * @var string
     */
    private string $pwd_hashed = "";

    /**
     * @var string
     */
    private string $password = "";

    /**
     * @param array $config
     */
    public function __construct(
        private array $config = [
            "algo" => HashAlgorithm::DEFAULT,
            "cost" => "",
            "memory_cost" => "",
            "time_cost" => "",
            "threads" => ""
        ]
    ) {
        foreach ($config as $key => $value) {
            if (!isset($this->config[$key])) {
                throw new HashException("Key '$key' not exists");
            }

            $this->options = $this->config;
            $this->algo = $this->config['algo'];
        }

        $this->setPepper();
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

        $this->pwd_hashed = password_hash($pwd_peppered, $this->algo);

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
     * @return mixed
     */
    public function getHashInfo(): mixed
    {
        return password_get_info($this->pwd_hashed);
    }

    /**
     * Verify if the hash generated with `createHash` is valid
     * 
     * @param null|string $password
     * @param null|string $hash
     * 
     * @return bool
     */
    public function verifyHash(?string $password = null, ?string $hash = null): bool
    {
        if (is_null($password)) {
            $password = $this->password;
        }

        if (is_null($hash)) {
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
        }

        return false;
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
     * @return string|false
     */
    public function needsRehash(string $password, string $hash): string|false
    {
        if (password_needs_rehash($hash, $this->algo)) {
            $newHash = $this->createHash($password)->getHash();

            return $newHash;
        }

        return false;
    }
}
