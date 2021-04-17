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
     * Construct
     */
    public function __construct()
    {
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
     * Creates a password peppered using the entered password and the secret entry. To return the 
     * information of the created hash, use `$info` as `true`. 
     * 
     * @param string $password
     * 
     * @return mixed
     */
    public function createHash(string $password, bool $info = false)
    {
        if (empty($this->algo)) {
            $this->algo = self::DEFAULT;
        }

        $pwd_peppered = $this->passwordPeppered($password);
        $pwd_hashed = password_hash($pwd_peppered, $this->algo, $this->options);

        if ($info == true) {
            return password_get_info($pwd_hashed);
        }

        return $pwd_hashed;
    }

    /**
     * Checks whether the hash in `$hash` is valid. If the hash entered does not match the options 
     * received in the `createHash` method, it is possible to regenerate a new hash in `$verify_needs_rehash`. 
     * This function also makes timing attacks difficult. 
     * 
     * @param string $password
     * @param string $hash
     * @param bool $verify_needs_rehash
     * 
     * @return mixed
     */
    public function verifyHash(string $password, $hash, bool $verify_needs_rehash = false)
    {
        if (is_array($hash)) {
            throw new HashException("You are returning the hash information. Enter 'false' in the 'createHash' method");
        }

        if (empty($this->algo)) {
            $this->algo = self::DEFAULT;
        }

        $pph_strt = microtime(true);
        $pwd_peppered = $this->passwordPeppered($password);

        if (password_verify($pwd_peppered, $hash)) {
            try {
                return $this->needsRehash($password, $hash, $verify_needs_rehash);
            } finally {
                $end = (microtime(true) - $pph_strt);
                $wait = bcmul((1 - $end), 1000000);  // usleep(250000) 1/4 of a second
                usleep($wait);

                #echo "<br>Execution time:" . (microtime(true) - $pph_strt) . "; ";
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
     * @param bool $verify
     * 
     * @return mixed
     */
    private function needsRehash(string $password, string $hash, bool $verify)
    {
        if ($verify == true) {
            if (password_needs_rehash($hash, $this->algo)) {
                $newHash = $this->createHash($password);

                return $newHash;
            } else {
                return true;
            }
        } else {
            return true;
        }
    }

    /**
     * @param string $pepper
     * 
     * @return string
     */
    private function createPepper(string $pepper): string
    {
        $hash = openssl_encrypt($pepper, "AES-128-CBC", pack('a16', 'secret'), 0, pack('a16', 'secret2'));

        return $hash;
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
        $pwd_peppered = hash_hmac("sha256", $password, $this->getPepper());

        return $pwd_peppered;
    }
}
