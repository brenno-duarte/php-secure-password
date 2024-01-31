<?php

namespace SecurePassword;

use SecurePassword\{
    PepperTrait,
    HashAlgorithm
};

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
     * @var int|null|null
     */
    private ?int $cost_min_ms = null;

    /**
     * @param array $config
     */
    public function __construct(
        private array $config = [
            "algo" => HashAlgorithm::DEFAULT,
            "cost" => "10",
            "memory_cost" => "",
            "time_cost" => "",
            "threads" => ""
        ]
    ) {
        $this->options = $this->config;
        $this->algo = $this->config['algo'];
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
        $this->pwd_hashed = password_hash($pwd_peppered, $this->algo, $this->options);

        return $this;
    }

    /**
     * Return password hash
     * 
     * @return string
     */
    public function getHash(): string
    {
        return $this->pwd_hashed;
    }

    /**
     * Returns information about the given hash
     * 
     * @param string|null $hash
     * 
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
     * @param int $wait
     * 
     * @return bool
     */
    public function verifyHash(?string $password = null, ?string $hash = null, int $wait_microseconds = 250000): bool
    {
        if (is_null($password)) {
            $password = $this->password;
        }

        if (is_null($hash)) {
            $hash = $this->pwd_hashed;
        }

        if (password_get_info($hash)['algoName'] === 'unknown') {
            return false;
        }

        $pwd_peppered = $this->passwordPeppered($password);
        $res = password_verify($pwd_peppered, $hash);
        usleep($wait_microseconds);

        return $res;
    }

    /**
     * Here's a quick little function that will help you determine what cost parameter you should be 
     * using for your server to make sure you are within this range.
     * 
     * @param string $password
     * @param string $crypt
     * @param int $min_ms
     * 
     * @return int
     */
    public static function getOptimalBcryptCost(
        string $password,
        int $min_ms = 250
    ): int {
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
            return $this->createHash($password)->getHash();
        }

        return false;
    }

    /**
     * This code will benchmark your server to determine how high of a cost you can
     * afford. You want to set the highest cost that you can without slowing down
     * you server too much. 10 is a good baseline, and more is good if your servers
     * are fast enough. The code below aims for ≤ 350 milliseconds stretching time,
     * which is an appropriate delay for systems handling interactive logins.
     * 
     * @param string $password
     * 
     * @return int
     */
    public static function benchmarkCost(string $password): int
    {
        $timeTarget = 0.350; // 350 milliseconds
        $cost = 10;

        do {
            $cost++;
            $start = microtime(true);
            password_hash($password, PASSWORD_BCRYPT, ["cost" => $cost]);
            $end = microtime(true);
        } while (($end - $start) < $timeTarget);

        return $cost;
    }
}
