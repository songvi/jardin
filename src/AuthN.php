<?php

namespace Vuba\AuthN;

use Doctrine\ORM\EntityManager;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Vuba\AuthN\AuthStack\AuthLdap;
use Vuba\AuthN\AuthStack\AuthMySQL;
use Vuba\AuthN\AuthStack\AuthStack;
use Vuba\AuthN\Exception\RetCode;
use Vuba\AuthN\Service\ConfigService;
use Vuba\AuthN\Service\IConfService;
use Vuba\AuthN\User\UserFSM;
use Vuba\AuthN\User\UserObject;
use Vuba\AuthN\UserStorage\UserStorageSql;
use Vuba\AuthN\UserUserObject;

/**
 * Class AuthN
 * @package Vuba\AuthN
 */
class AuthN
{
    /**
     * Login
    *Register
    *Activate account
    *Resend activation email
    *Reset password
    *Change password
    *Change email address
    *Delete account
    *Logout
     *
     */

    private $userStorage;
    private $authStack;

    /**
     * @param IConfService $confService
     */
    public function __construct(IConfService $confService){
        switch(strtolower($confService->getAuthType())){
            case 'sql':
                $authsql = new AuthMySQL($confService->getSqlConnection(), $confService->getAuthStorage());
                $this->authStack = new AuthStack($authsql);

                break;

            case 'ldap':
                $this->authStack = new AuthStack();
                $auth = new AuthLdap();
                $this->authStack->addAuth($auth, $auth->authSourceName);
                break;
            default:
                break;
        }

        switch($confService->getUserStorageType()){
            case 'sql':
                $userStorage = new UserStorageSql($confService);
                $this->userStorage = $userStorage;
                break;
            case 'ldap':
                break;
            default:
                break;
        }

    }

    /**
     * @param $uid
     * @return bool
     * @throws \Finite\Exception\StateException
     *
     */
    public function register($uid){
        if($this->authStack->getDefaultAuth()->isExist($uid)) return false;
        $user = new UserObject();
        $user->setExtuid($uid);
        $user->setUuid(UserObject::calculeUuid($uid,$this->authStack->getDefaultAuth()->authSourceName));
        $user->setAuthSourceName($this->authStack->getDefaultAuth()->authSourceName);
        $user->setDispatcher(new EventDispatcher());

        $userfsm = UserFSM::getMachine($user);
        if($userfsm->can(UserFSM::TRANSITION_REGISTER)){
            $userfsm->apply(UserFSM::TRANSITION_REGISTER );
            $user = $userfsm->getObject();
            $this->userStorage->save($user);
            $this->authStack->getDefaultAuth()->createUser($uid,'');
            return true;
        }
        else{
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }
        return false;
    }

    public function reSend($uid){
        if(is_null($uid)) return false;
        $user = $this->userStorage->loadUser($uid);
        if(is_null($user)) return false;
        $user->setDispatcher(new EventDispatcher());

        $userfsm = UserFSM::getMachine($user);
        if($userfsm->can(UserFSM::TRANSITION_RESEND)){
            $userfsm->apply(UserFSM::TRANSITION_RESEND);
            $this->userStorage->save($userfsm->getObject());
            return true;
        }
        else{
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }
    }

    public function confirm($uid, $password, $activationCode){
        if(is_null($password)) return false;
        $user = $this->userStorage->loadUser($uid);

        if(empty($activationCode)) throw new \Exception("activationkey_invalid");
        if($user instanceof UserObject){
            if(strtolower($activationCode) !== $user->getActivationCode()){
                throw new \Exception("activationkey_incorrect");
            }
        }

        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        if(!$userfsm->can(UserFSM::TRANSITION_CONFIRM)) {
            $this->authStack->getDefaultAuth()->updatePassword($uid, $password);
            $userfsm->apply(UserFSM::TRANSITION_CONFIRM);
            $this->userStorage->save($userfsm->getObject());
            return true;
        }
        else{
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }
    }

    public function login($uid, $password){
        if(is_null($uid) || is_null($password)) return false;

        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if(!$userfsm->can(UserFSM::TRANSITION_LOGIN)) {
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }

        if($this->authStack->getDefaultAuth()->login($uid, $password)){
            $userfsm->apply('login');
            $this->userStorage->save($userfsm->getObject());
            return true;
        }
        else{
            // Login with wrong password
            $user = $userfsm->getObject();
            if($user instanceof UserObject){
                $user->setLoginFailedCount($user->getLoginFailedCount() + 1);
            }
        }
        return false;
    }

    public function modify($uid, $kv = array()){
        if(is_null($uid)) return false;

        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if(!$userfsm->can(UserFSM::TRANSITION_MODIFY)) {
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }
        // set user by $kv array
        /*
            'sub',
            'name',
            'given_name',
            'family_name',
            'middle_name',
            'nickname',
            'preferred_username',
            'profile',
            'email',
            'email_verified',
            'gender',
            'birthdate',
            'zoneinfo',
            'locale',
            'phone_number',
            'address',
            'preferred_lang'
            'preferred_theme'
         */
        $allowedAttributes = $userfsm->getCurrentState()->getProperties();
        $user = $userfsm->getObject();
        if($user instanceof UserObject){
            foreach($allowedAttributes as $key => $value){
                if(isset($kv[$value])){
                    switch ($value){
                        case 'sub':
                            $user->setSub($kv[$value]);
                            break;
                        case 'name':
                            $user->setName($kv[$value]);
                            break;
                        case 'given_name':
                            $user->setGivenName($kv[$value]);
                            break;
                        case 'family_name':
                            $user->setFamilyName($kv[$value]);
                            break;
                        case 'middle_name':
                            $user->setMiddleName($kv[$value]);
                            break;
                        case 'nickname':
                            $user->setNickname($kv[$value]);
                            break;
                        case 'preferred_username':
                            $user->setPreferredUsername($kv[$value]);
                            break;
                        case 'profile':
                            $user->setProfile($kv[$value]);
                            break;
                        case 'email':
                            $user->setEmail($kv[$value]);
                            break;
                        case 'email_verified':
                            $user->setEmailVerified($kv[$value]);
                            break;
                        case 'gender':
                            $user->setGender($kv[$value]);
                            break;
                        case 'birthdate':
                            $user->setBirthdate($kv[$value]);
                            break;
                        case 'zoneinfo':
                            $user->setZoneinfo($kv[$value]);
                            break;
                        case 'locale':
                            $user->setLocale($kv[$value]);
                            break;
                        case 'phone_number':
                            $user->setPhoneNumber($kv[$value]);
                            break;
                        case 'address':
                            $user->setAddress($kv[$value]);
                            break;
                        case 'preferred_lang':
                            $user->setPreferredLang($kv[$value]);
                            break;
                        case 'preferred_theme':
                            $user->setPreferredTheme($kv[$value]);
                            break;
                        default;
                            break;
                    }
                }
            }
        }
        $userfsm->apply(UserFSM::TRANSITION_MODIFY);
        $this->userStorage->save($userfsm->getObject());

        return true;
    }

    public function resetpw($uid, $oldpassword, $newpassword){
        if(is_null($uid) ||
        is_null($oldpassword) ||
        is_null($newpassword)) return false;

        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if(!$userfsm->can(UserFSM::TRANSITION_RESETPASSWORD)) {
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }

        if($this->authStack->getDefaultAuth()->checkPassword($uid, $oldpassword)){
            $this->authStack->getDefaultAuth()->updatePassword($uid, $newpassword);
            return true;
        }

        return false;
    }
    
    public function forgotpw($uid){
        if(is_null($uid)) return false;

        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if(!$userfsm->can(UserFSM::TRANSITION_FORGOTPW)){
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }
        
        $userfsm->apply(UserFSM::TRANSITION_FORGOTPW);
        $this->userStorage->save($userfsm->getObject());
            
        return true;
    }

    public function reSendForgotpw($uid){
        if(is_null($uid)) return false;

        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if(!$userfsm->can(UserFSM::TRANSITION_RESEND_FORGOTPW)) {
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }

        $userfsm->apply(UserFSM::TRANSITION_RESEND_FORGOTPW);
        $this->userStorage->save($userfsm->getObject());

        return true;
    }

    public function lock($uid){
        if(is_null($uid)) return false;

        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if(!$userfsm->can(UserFSM::TRANSITION_LOCK)) {
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }

        $userfsm->apply(UserFSM::TRANSITION_LOCK);
        $this->userStorage->save($userfsm->getObject());
        return true;
    }

    public function unlock($uid){
        if(is_null($uid)) return false;

        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if(!$userfsm->can(UserFSM::TRANSITION_UNLOCK)) {
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }

        $userfsm->apply(UserFSM::TRANSITION_UNLOCK);
        $this->userStorage->save($userfsm->getObject());
        return true;
    }

    public function close($uid){
        if(is_null($uid)) return false;

        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if(!$userfsm->can(UserFSM::TRANSITION_CLOSE)) {
            throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
        }

        $userfsm->apply(UserFSM::TRANSITION_CLOSE);
        $this->userStorage->save($userfsm->getObject());
        return true;
    }

    /**
     *
     */
    public function getUserList(){

    }

    public function deletUser($uid){
        $user = $this->userStorage->loadUser($uid);
        if (!$this->authStack->getDefaultAuth()->isExist($uid) || is_null($user)) {
            throw new \Exception("User does not exist", RetCode::USER_NOT_EXIST);
        }
        $this->authStack->getDefaultAuth()->delete($uid);
        $this->userStorage->deleteUser($user);
    }

    public function searchUser($criterias = array()){
        $users = $this->userStorage->search($criterias);
        return $users;
    }
    public function loadUser($uid){
        if(is_null($uid)) return;
        return $this->userStorage->loadUser($uid);
    }
}
