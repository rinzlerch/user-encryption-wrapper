<?php
namespace Rinzler\UserEncryption;

use Cookie;
use Auth;
use View;
use Redirect;

use Illuminate\Contracts\Encryption\DecryptException;

use \ParagonIE\Halite\KeyFactory as KeyFactory;
use \ParagonIE\Halite\Asymmetric\Crypto as Crypto;
use \ParagonIE\Halite\HiddenString as CryptoHiddenString;
use \ParagonIE\Halite\Asymmetric\EncryptionPublicKey as EncryptionPublicKey;
use \ParagonIE\Halite\Asymmetric\EncryptionSecretKey as EncryptionSecretKey;
use \ParagonIE\Halite\HiddenString as HiddenString;
use \ParagonIE\Halite\Alerts\InvalidKey as InvalidKey;

/**
 * UserEncryption class is used to create a wrapper between 
 * the in-built PHP OpenSSL extension to generate a master 
 * public/private key, and to connect to Paragonie's Halite
 * (libsodium) extension to generate a public/private encryption
 * key. 
 */
class UserEncryption {
    /**
     * Generates a OpenSSL public/private encryption key using the provided passphrase.
     * 
     * @value $passphrase
     * @return array(private, public, type)
     */
    public function generateEncryptionKey($passphrase) {
        $config = array(
            "digest_alg" => "sha256",
            "private_key_bits" => 4096,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privKey, $passphrase);
        $pubKey = openssl_pkey_get_details($res);

        return array(
            'private' => base64_encode($privKey),
            'public' => base64_encode($pubKey["key"]),
            'type' => $config,
        );
    }

    /**
     * Uses the Halite library to generate a public/private encryption key
     * used to encrypt any data that the user creates.
     * 
     * @return array(private, public)
     */
    public function generateAESKey() {
        $keypair = KeyFactory::generateEncryptionKeyPair();
        $secret = $keypair->getSecretKey();
        $public = $keypair->getPublicKey();

        $publicString = sodium_bin2hex($public->getRawKeyMaterial());
        $secretString = sodium_bin2hex($secret->getRawKeyMaterial());

        return array(
            'private' => $secretString,
            'public' => $publicString,
        );
    }

    /**
     * Decrypts the master key when a correct passphrase is entered.
     * 
     * @value $privateKey, $passphrase
     * @return boolean
     */
    public function decryptMasterKey($privateKey, $passphrase) {
        $encryptedKey = openssl_pkey_get_private(base64_decode($privateKey), $passphrase);

        if ($encryptedKey) {
            $decryptedKey = openssl_pkey_export($encryptedKey, $key);
            return $key;
        } else {
            return false;
        }
    }

    /**
     * Encrypts the encryption key that is used to encrypt all data.
     * 
     * @value $data, $key
     * @return string
     */
    public function encryptAESKey($data, $key)
    {
        openssl_public_encrypt($data, $encryptedData, $key, OPENSSL_PKCS1_OAEP_PADDING);
        return base64_encode($encryptedData);
    }

    /**
     * Decrypts the encryption key that is used to encrypt all data.
     * 
     * @value $data, $key
     * @return string
     */
    public function decryptAESKey($data, $key)
    {   
        openssl_private_decrypt(base64_decode($data), $decryptedData, $key, OPENSSL_PKCS1_OAEP_PADDING);
        return $decryptedData;
    }

    /**
     * Used to encrypt any strings entered with the public 
     * encryption key from user cookie "secret_key".
     * 
     * @value $data, $publicKeyString
     * @return string
     */
    public function encryptString($data, $publicKeyString) {
        $publicKey = new EncryptionPublicKey(
            new HiddenString(
                sodium_hex2bin($publicKeyString)
            )
        );
        
        $encryptedString = Crypto::seal(new CryptoHiddenString($data), $publicKey);
        return $encryptedString;
    }

    /**
     * Decrypts any strings that are encrypted with the public key
     * using the private key saved as a cookie, returns data as text.
     * 
     * @value $data
     * @return string
     */
    public function decryptString($data) {
        try {
            $decryptedKey = decrypt($this->secretKeyFromLocal());
        } catch (DecryptException $e) {
            setcookie('secret_key', null, -1, '/');
            die(redirect()->back());
        }

        $secretKey = new EncryptionSecretKey(
            new HiddenString(
                sodium_hex2bin($decryptedKey)
            )
        );
        
        try {
            $decryptedString = Crypto::unseal($data, $secretKey);
        } catch (InvalidKey $e) {
            setcookie('secret_key', null, -1, '/');
            die(redirect()->back());
        }

        return $decryptedString;
    }

    /**
     * Gets the private key from the user's cookies.
     * 
     * @return string
     */
    private function secretKeyFromLocal() {
        $key = Cookie::get('secret_key');
        if ($key) {
            return $key;
        } else {
            return redirect()->route('user-encryption.decrypt');
        }
    }
}