<?php

namespace Vuba\AuthN\AuthStack;

use Vuba\AuthN\Service\IConfService;
use Vuba\AuthN\User\UserObject;

class AuthStack extends AbstractAuth
{
    protected $authstack = array();
    protected $userStorage;

    /**
     * @param AbstractAuth $auth
     * @param $order
     */
    public function __construct(IConfService $confService)
    {
        if(!empty($confService) && count($confService->getAuth()) > 0){
            foreach ($confService->getAuth() as $auth){
                switch(strtolower($auth['type'])){
                    case 'sql':
                        $authsql = new AuthMySQL($auth['config']);
                        $authsql->authSourceName = $auth['name'];
                        $this->addAuth($authsql, $auth['order']);
                        break;
                    case 'ldap':
                        $authldap = new AuthLdap($auth['config']);
                        $authldap->authSourceName = $auth['name'];
                        $this->addAuth($authldap, $auth['order']);
                        break;
                    default:
                        break;
                }
            }
        }
        $this->sort();
    }


    /**
     * sort auth by order
     */
    protected function sort()
    {
        ksort($this->authstack);
    }

    protected function getMaxOrder(){
        $max = 0;
        foreach($this->authstack as $key => $value){
            if ($max < $key ) $max = $key;
        }
        return $max;
    }

    /**
     * @param AbstractAuth $auth
     * @param $order
     */
    public function addAuth(AbstractAuth $auth, $order = null)
    {
        $maxIndex = $this->getMaxOrder();
        if(is_null($order) || isset($this->authstack[$order])){
            $this->authstack[$maxIndex] = $auth;
        }
        else {
            $this->authstack[$order] = $auth;
        }
    }

    /**
     * @return AbstractAuth
     */
    public function getDefaultAuth(){
        if (isset($this->authstack[0])){
            return $this->authstack[0];
        }
        return null;
    }

    /**
     * @param $id
     * @param $passphrase
     * @return bool
     */
    public function login($uid, $passphrase){
        foreach ($this->authstack as $auth)
        {
            if($auth instanceof AbstractAuth){
                if($auth->login($uid, $passphrase)) {
                    return array(
                        'uuid' => UserObject::calculeUuid($uid, $auth->authSourceName),
                        'uid' => $uid,
                        'authsource' => $auth->authSourceName,
                    );
                }
            }
        }
        return null;
    }

    public function userExist($uid){
        foreach ($this->authstack as $auth)
        {
            if($auth instanceof AbstractAuth){
                if($auth->isExist($uid)) return array(
                    'uid' => $uid,
                    'authsource' => $auth->authSourceName,
                    'uuid' => UserObject::calculeUuid($uid, $auth->authSourceName),
                );
            }
        }
        return null;
    }

    /**
     *
     */
    public function createUser($uid, $passphrase)
    {
        $defaultAuth = $this->getDefaultAuth();
        if(!empty($defaultAuth) && !($defaultAuth->isReadOnly())){
            return $defaultAuth->createUser($uid, $passphrase);
        }
    }

    public function setUserPassword($uid, $passphrase)
    {
        $defaultAuth = $this->getDefaultAuth();
        if(!empty($defaultAuth) && !($defaultAuth->isReadOnly())){
            return $defaultAuth->setUserPassword($uid, $passphrase);
        }
    }

    public function updatePassword($uid, $passphrase)
    {
        $defaultAuth = $this->getDefaultAuth();
        if(!empty($defaultAuth) && !($defaultAuth->isReadOnly())){
            return $defaultAuth->updatePassword($uid, $passphrase);
        }
    }
}
