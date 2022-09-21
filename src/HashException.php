<?php

namespace SecurePassword;

class HashException extends \Exception
{
    public function __toString()
    {
        return __CLASS__ . ": {$this->message}\n";
    }
}
