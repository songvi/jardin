<?php

namespace Vuba\AuthN\AuthStack;

use Dibi\Connection;
use Defuse\Crypto\Key;
use ParagonIE\PasswordLock\PasswordLock;
use Vuba\AuthN\User\UserFSM;

class AuthMySQL extends AbstractAuth
{
    protected $key;

    /**
     * @var array(
     *  host = address/ irp
     *  port = port (default 3306
     *  username = username
     *  password = password
     *  database = databasename
     *  table = tablename
     *  useridcolumn = columnname
     *  passwordcolumn = column password
     *
     *  password hash algo = MD5|SHA256|Bcrypt|bcrypt + sha256 + base64
     *
     */
    protected $conn;

    public function __construct($config)
    {
        $sqlConnection  = $config['sqlconnection'];

        $cfg = $sqlConnection;
        $cfg['databasename']        = $sqlConnection['dbname'];
        $cfg['database']            = $sqlConnection['dbname'];
        $cfg['table']               = $config['table'];
        $cfg['useridcolumn']        = $config['usercol'];
        $cfg['passwordcolumn']      = $config['passwordcol'];

        $this->conn = new Connection($cfg);
        if($config['asciikey']) $asciikey = $config['asciikey'];
        $this->key = KEY::loadFromAsciiSafeString($asciikey);
    }

    public function isReadOnly(){
        return false;
    }

    public function createUser($uid, $passphrase = null){
        if(!$this->isExist($uid)){
            if($passphrase) {
                $pass = $this->getHash($passphrase);
            }else{
                $pass = null;
            }
            $data = ["uid" => $uid,
                "password" => $pass,
                "state" => UserFSM::USER_STATE_INIT
            ];

            $result = $this->conn->query("INSERT INTO [users] ", $data);
            return true;
        }
        return false;
    }

    public function setUserPassword($uid, $passphrase){
        if(empty($uid) || empty($passphrase)) return false;

        if(!$this->isExist($uid)){
            $pass = $this->getHash($passphrase);
            $data = ["uid" => $uid,
                "password" => $pass,
                "state" => UserFSM::USER_STATE_INIT];

            $result = $this->conn->query("INSERT INTO [users] ", $data);
        }
    }

    public function isExist($uid){
        $result = $this->conn->query("SELECT COUNT(*) from [users] WHERE [uid] = %s", $uid);
        return (intval($result->fetchSingle()) > 0);
    }

    public function countUser($state = UserFSM::USER_STATE_NORMAL){
        $result = $this->conn->query("SELECT COUNT(*) from [users] WHERE [state] = %s", $state);
        return intval($result->fetchSingle());
    }

    public function updatePassword($uid, $password){
        $result = $this->conn->query("UPDATE [users] set [password] = %s WHERE [uid] = %s", $this->getHash($password), $uid);
    }

    protected function getHash($clearPassPhrase){
        return PasswordLock::hashAndEncrypt($clearPassPhrase, $this->key);
    }

    public function login($uid, $passphrase){
        return $this->checkPassword($uid, $passphrase, $this->key);
    }

    /**
     *
     */
    public function checkPassword($uid, $passphrase, Key $key = null){
        if(!$encryptedPassPhrase = $this->getPassPhrase($uid)) return false;
        return PasswordLock::decryptAndVerify($passphrase, $encryptedPassPhrase, $this->key);
    }

    protected function getPassPhrase($uid){
        $result = $this->conn->query("SELECT [password] FROM users WHERE [uid] = %s", $uid);
        $pass = $result->fetchSingle();
        return $pass;
    }

    public function delete($uid){
        if($this->isExist($uid)){
            $result = $this->conn->query("DELETE FROM [users] WHERE [uid] = %s", $uid);
            return $result;
        }
        return false;
    }

    public function listUser($state){
        $result = $this->conn->query("SELECT [uid] from [users] WHERE [state] = %s", $state);
        return intval($result->fetchSingle());
    }
}
