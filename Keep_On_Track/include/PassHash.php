<?php
 
class PassHash {
 
    // blowfish algorithm. Strong symettric key block cipher. Combined with salt.
    private static $algo = '$2a';
    // cost parameter
    private static $cost = '$10';
 
    // Generate a unique salt. Mainly for internal use
    // generated to make a common password uncommon. 
    // Therefore difficult for hashed value to be found in look up table
    public static function unique_salt() {
        return substr(sha1(mt_rand()), 0, 22);
    }
 
    // this will be used to generate a hash
    public static function hash($password) {
 
        return crypt($password, self::$algo .
                self::$cost .
                '$' . self::unique_salt());
    }
 
    // this will be used to compare a password against a hash
    public static function check_password($hash, $password) {
        $full_salt = substr($hash, 0, 29);
        $new_hash = crypt($password, $full_salt);
        return ($hash == $new_hash);
    }
 
}
 
?>