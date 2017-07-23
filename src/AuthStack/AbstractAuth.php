<?php

namespace Vuba\AuthN\AuthStack;

use Defuse\Crypto\Key;
use Ramsey\Uuid\Uuid;

abstract class AbstractAuth
{

    public $authSourceName;

    public function __construct($authSourceName)
    {
        $this->authSourceName = $authSourceName;
    }

    /**
     * @param $id
     * @param $passphrase
     * @return UserObject or false
     *
     */
    public function checkPassword($uid, $passphrase, Key $key = null)
    {
        return false;
    }


    /**
     * @param $uid
     * @param $passphrase
     * @return bool
     */
    public function createUser($uid, $passphrase)
    {

        return false;
    }

    /**
     * @param $uid
     * @return bool
     */
    public function isExist($uid)
    {

        return false;
    }

    /**
     * @param $uid
     */
    public function delete($uid)
    {

    }

    /**
     * @param $uid
     * @return \Ramsey\Uuid\UuidInterface
     */
    public function getUuid($uid)
    {
        $uuid = Uuid::uuid5(strtolower(trim($this->authSourceName)), strtolower(trim($uid)));
        return $uuid;
    }

    /**
     *
     */
    public function sendConfirmation(){

    }

    public function lock($uid){

    }

    public function updatePassword($uid, $password){

    }
}
