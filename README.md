# PHP SecurePassword

SecurePassword is a PHP component for creating strong passwords using modern encryption.

## Why use this component?

Unlike just using `password_hash`, SecurePassword adds a secret entry (commonly called a pepper) to make it difficult to break the generated hash.

## Requirements

PHP >= 8.0

## Installing via Composer

```
composer require brenno-duarte/php-secure-password
```

## How to use

The code below shows an example for creating the hash. The `createHash` method generates the password hash along with the "peeper", and the `getHash` method returns the generated hash.

```php
use SecurePassword\SecurePassword;

$password = new SecurePassword();
$hash = $password->createHash('my_password')->getHash();

/** Return string */
var_dump($hash);
```

## Settings

You can change encryption settings without using the methods that will be listed below. To do this, enter the following code in the constructor:

```php
use SecurePassword\HashAlgorithm;

$config = [
    'algo' => HashAlgorithm::DEFAULT,
    'cost' => 10,
    'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
    'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,
    'threads' => PASSWORD_ARGON2_DEFAULT_THREADS
];

$password = new SecurePassword($config);
```

You can use the following encryptions: `HashAlgorithm::DEFAULT`, `HashAlgorithm::BCRYPT`, `HashAlgorithm::ARGON2I`, `HashAlgorithm::ARGON2ID`.

## Changing the encryption algorithm

**NOTE: If you are using the settings passed in the constructor then you can ignore the code below.**

You can change the type of algorithm used to generate the hash. It is possible to use `PASSWORD_BCRYPT`,` PASSWORD_ARGON2I`, `PASSWORD_ARGON2ID` and even `PASSWORD_DEFAULT`.

`useDefault()` will use standard encryption
`useBcrypt()` will use Bcrypt encryption
`useArgon2()` will use Argon2 encryption
`useArgon2(null)` passing `true` will use Argon2d encryption 

```php
# standard encryption
$hash = $password->useDefault()->createHash('my_password')->getHash();

# Bcrypt encryption
$hash = $password->useBcrypt()->createHash('my_password')->getHash();

# Argon2 encryption
$hash = $password->useArgon2()->createHash('my_password')->getHash();

# Argon2d encryption (with `true`)
$hash = $password->useArgon2(true)->createHash('my_password')->getHash();
```

If the type of algorithm is not provided, the default encryption will be 'PASSWORD_DEFAULT'.

## Returns information about the given hash

To return the information of the created hash, use `getHashInfo` method.

```php
$hash = $password->createHash('my_password')->getHashInfo();

/** Return array */
var_dump($hash);
```

## Verifies that a password matches a hash

To verify that the hash generated with `createHash` is valid, you can use `verifyHash` in two ways:

```php
# First way
$hash = $password->createHash('my_password')->getHash();
$res = $password->verifyHash('my_password', $hash);

# Second way
$hash = $password->createHash('my_password')->verifyHash();

/** Return bool */
var_dump($res);
```

**NOTE: If you are using the settings passed in the constructor then you can ignore the code below.**

You can change the type of algorithm that will be used to check the hash.

```php
$hash = $password->useArgon2()->createHash('my_password')->getHash();
$res = $password->useArgon2()->verifyHash('my_password', $hash);

/** Return bool */
var_dump($res);
```

If the encryption type has been changed, you can generate a new hash with the new encryption. The `needsHash()` method checks whether the reported hash needs to be regenerated. Otherwise, it will return false.

```php
$hash = $password->useArgon2()->createHash('my_password')->getHash();
$needs = $password->useDefault()->needsRehash('my_password', $hash);

/** Return bool or string */
var_dump($res);
```

## Adding options

**NOTE: If you are using the settings passed in the constructor then you can ignore the code below.**

Add options in the `useDefault`, `useBcrypt` and `useArgon2` methods.

- useDefault: default options, use an array.
- useBcrypt: you can change `$cost`. The default is `10`.
- useArgon2: you can change `$memory_cost`, `$time_cost` and `$threads`. The default is the constants `PASSWORD_ARGON2_DEFAULT_MEMORY_COST`, `PASSWORD_ARGON2_DEFAULT_TIME_COST` and `PASSWORD_ARGON2_DEFAULT_THREADS`.

```php
# standard encryption
$hash = $password->useDefault([])->createHash('my_password');

# Bcrypt encryption
$hash = $password->useBcrypt(10)->createHash('my_password');

# Argon2 encryption
$hash = $password->useArgon2(false, PASSWORD_ARGON2_DEFAULT_MEMORY_COST, PASSWORD_ARGON2_DEFAULT_TIME_COST, PASSWORD_ARGON2_DEFAULT_THREADS)->createHash('my_password');

# Argon2d encryption (with `true`)
$hash = $password->useArgon2(true, PASSWORD_ARGON2_DEFAULT_MEMORY_COST, PASSWORD_ARGON2_DEFAULT_TIME_COST, PASSWORD_ARGON2_DEFAULT_THREADS)->createHash('my_password');
```

## Changing the secret entry (recommended)

It is recommended to change the secret entry (or pepper) that will be added to your password. Use `setPepper` to change.

```php
$password = new SecurePassword();
$password->setPepper('new_pepper');
```

## Getting the ideal encryption cost

Here's a quick little function that will help you determine what cost parameter you should be using for your server to make sure you are within this range.

```php
$password = new SecurePassword();
$cost = $password->getOptimalBcryptCost();

/** Return int */
var_dump($cost);
```

## License

MIT
