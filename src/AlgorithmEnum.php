<?php

namespace SecurePassword;

enum AlgorithmEnum: string
{
    case DEFAULT = "default";
    case BCRYPT  = PASSWORD_BCRYPT;
    case ARGON2I = PASSWORD_ARGON2I;
    case ARGON2ID = PASSWORD_ARGON2ID;
}