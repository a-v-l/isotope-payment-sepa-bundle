<?php

declare(strict_types = 1);

namespace Gruschit\Contao\Isotope\Payment\Sepa;

class Encryption
{
    const KEY = 'KJDgFBeGZHlqA0wvdFjZomVitSPDbEwZ';

    public static function encrypt(string $data): string
    {
        $container = \Contao\System::getContainer();
        $key = $container->hasParameter('sepa_encryption_key') ? $container->getParameter('sepa_encryption_key') : self::KEY;
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        $cipherText = sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
            (string) $data,
            $nonce,
            $nonce,
            $key
        );

        return $nonce . $cipherText;
    }

    public static function decrypt(string $data): string
    {
        $container = \Contao\System::getContainer();
        $key = $container->hasParameter('sepa_encryption_key') ? $container->getParameter('sepa_encryption_key') : self::KEY;
        $nonce = mb_substr($data, 0, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, '8bit');
        $payload = mb_substr($data, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, null, '8bit');

        try {
            $plainText = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
                $payload,
                $nonce,
                $nonce,
                $key
            );
        } catch (\SodiumException $e) {
            $plainText = '';
        }

        return false !== $plainText ? $plainText : '';
    }
}
