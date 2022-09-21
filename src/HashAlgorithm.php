<?php

namespace SecurePassword;

abstract class HashAlgorithm
{
    const DEFAULT = PASSWORD_DEFAULT;
    const BCRYPT  = PASSWORD_BCRYPT;
    const ARGON2I = PASSWORD_ARGON2I;
    const ARGON2ID = PASSWORD_ARGON2ID;

    /**
     * @var mixed
     */
    protected mixed $algo;

    /**
     * @var array
     */
    protected array $options = [];

    /**
     * @param array $options
     * 
     * @return SecurePassword
     */
    public function useDefault(array $options = []): SecurePassword
    {
        $this->options = $options;
        $this->algo = self::DEFAULT;

        return $this;
    }

    /**
     * @param int $cost
     * 
     * @return SecurePassword
     */
    public function useBcrypt(int $cost = 10): SecurePassword
    {
        $this->options['cost'] = $cost;
        $this->algo = self::BCRYPT;

        return $this;
    }

    /**
     * @param bool $argon2d
     * @param int $memory_cost
     * @param int $time_cost
     * @param int $threads
     * 
     * @return SecurePassword
     */
    public function useArgon2(
        bool $use_argon2d = false,
        int $memory_cost = PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
        int $time_cost = PASSWORD_ARGON2_DEFAULT_TIME_COST,
        int $threads = PASSWORD_ARGON2_DEFAULT_THREADS
    ): SecurePassword {
        $this->options = [
            'memory_cost' => $memory_cost,
            'time_cost' => $time_cost,
            'threads' => $threads
        ];

        if ($use_argon2d == true) {
            $this->algo = self::ARGON2ID;
        } else {
            $this->algo = self::ARGON2I;
        }

        return $this;
    }
}
