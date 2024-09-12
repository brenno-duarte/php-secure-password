<?php

namespace SecurePassword;

use SensitiveParameter;
use SecurePassword\{PepperTrait, HashAlgorithm};

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
            "algo" => AlgorithmEnum::DEFAULT,
            "cost" => 12,
            "memory_cost" => "",
            "time_cost" => "",
            "threads" => ""
        ]
    ) {
        ($this->config["algo"] instanceof AlgorithmEnum) ?
            $algo_config = $this->config["algo"]->value :
            $algo_config = $this->config["algo"];

        $this->options = $this->config;
        $this->algo = ($algo_config == "default") ? PASSWORD_DEFAULT : $algo_config;
        $this->setPepper();
    }

    /**
     * Creates a password peppered using the entered password and the secret entry. 
     * 
     * @param string $password
     * 
     * @return SecurePassword
     */
    public function createHash(#[SensitiveParameter] string $password): SecurePassword
    {
        $this->password = $password;
        $pwd_peppered = $this->passwordPeppered($this->password);

        $this->pwd_hashed = password_hash(
            $pwd_peppered,
            $this->algo,
            $this->options
        );

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
    public function verifyHash(
        #[SensitiveParameter] ?string $password = null,
        #[SensitiveParameter] ?string $hash = null,
        int $wait_microseconds = 250000
    ): bool {
        if (is_null($password)) $password = $this->password;
        if (is_null($hash)) $hash = $this->pwd_hashed;
        if (password_get_info($hash)['algoName'] === 'unknown') return false;

        $pwd_peppered = $this->passwordPeppered($password);
        $result = password_verify($pwd_peppered, $hash);
        usleep($wait_microseconds);
        return $result;
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
    public static function getOptimalBcryptCost(#[SensitiveParameter] string $password, int $min_ms = 250): int
    {
        for ($i = 4; $i < 31; $i++) {
            $time_start = microtime(true);
            password_hash($password, PASSWORD_BCRYPT, ['cost' => $i]);
            $time_end = microtime(true);

            if (($time_end - $time_start) * 1000 > $min_ms) return $i;
        }

        return 12;
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
    public function needsRehash(
        #[SensitiveParameter] string $password,
        #[SensitiveParameter] string $hash
    ): string|false {
        return (password_needs_rehash($hash, $this->algo)) ?
            $this->createHash($password)->getHash() :
            false;
    }

    /**
     * This code will benchmark your server to determine how high of a cost you can
     * afford. You want to set the highest cost that you can without slowing down
     * you server too much. 12 is a good baseline, and more is good if your servers
     * are fast enough. The code below aims for ≤ 350 milliseconds stretching time,
     * which is an appropriate delay for systems handling interactive logins.
     * 
     * @param string $password
     * @param string $cost
     * 
     * @return int
     */
    public static function benchmarkCost(#[SensitiveParameter] string $password, int $cost = 12): int
    {
        $timeTarget = 0.350; // 350 milliseconds

        do {
            $cost++;
            $start = microtime(true);
            password_hash($password, PASSWORD_BCRYPT, ["cost" => $cost]);
            $end = microtime(true);
        } while (($end - $start) < $timeTarget);

        return $cost;
    }
}
