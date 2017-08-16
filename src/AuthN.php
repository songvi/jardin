<?php

namespace Vuba\AuthN;

use Doctrine\ORM\EntityManager;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Security\Core\User\User;
use Vuba\AuthN\AuthStack\AuthStack;
use Vuba\AuthN\Exception\ActionNotAllowOnState;
use Vuba\AuthN\Exception\ActivationKeyInvalid;
use Vuba\AuthN\Exception\RetCode;
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
        $this->authStack = new AuthStack($confService);

        $userStorage = $confService->getUserStorage();
        if(!empty($userStorage) && isset($userStorage['type'])) {
            switch (strtolower($userStorage['type'])) {
                case 'sql':
                    $Storage = new UserStorageSql($confService);
                    $this->userStorage = $Storage;
                    break;
                case 'ldap':
                    break;
                default:
                    break;
            }
        }
    }

    /**
     *
     */
    public function register($uid){
        // If user's already existed in auth sql and auth storage
        if($this->authStack->getDefaultAuth()->isExist($uid) ||
            $this->userStorage->isExist($uid)
        ) return false;

        $user = new UserObject();
        $user->setExtuid($uid);
        $user->setUuid(UserObject::calculeUuid($uid,$this->authStack->getDefaultAuth()->authSourceName));
        $user->setAuthSourceName($this->authStack->getDefaultAuth()->authSourceName);
        $user->setDispatcher(new EventDispatcher());

        $userfsm = UserFSM::getMachine($user);
        if($userfsm->can(UserFSM::TRANSITION_REGISTER)){
            $userfsm->apply(UserFSM::TRANSITION_REGISTER );
            $user = $userfsm->getObject();
            // Create user in storage
            // Create user in auth table
            return $this->userStorage->save($user) && $this->authStack->getDefaultAuth()->createUser($uid,'');
        }
        return false;
    }

    public function reSend($uid){
        if(is_null($uid)) return false;
        $user = $this->userStorage->loadUser($uid);
        if(empty($user)) return false;

        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        if($userfsm->can(UserFSM::TRANSITION_RESEND)){
            $userfsm->apply(UserFSM::TRANSITION_RESEND);
            $this->userStorage->save($userfsm->getObject());
            return true;
        }
        return false;
    }

    public function confirm($uid, $password, $activationCode){
        if(is_null($password)) return false;
        $user = $this->userStorage->loadUser($uid);
        if(empty($user)) return false;

        if(empty($activationCode)) throw new ActivationKeyInvalid("Activation key invalid");
        if($user instanceof UserObject){
            if(strtolower($activationCode) !== $user->getActivationCode()){
                throw new ActivationKeyInvalid("Activation key invalid");
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
            throw new ActionNotAllowOnState("Action not allowed on state");
        }
    }

    public function login($uid, $password){
        if(is_null($uid) || is_null($password)) return false;

        $user = $this->authStack->login($uid, $password);
        if($user !== null){
            $userObject = $this->userStorage->loadUser($uid, $user['authsource']);
            // if login successfully logs in but does not exist in storage,
            // Create new in storage
            if ($userObject === null) {
                $userObject = new UserObject();
                $userObject->setState(UserFSM::USER_STATE_NORMAL);
                $userObject->setUuid($user['uuid']);
                $userObject->setAuthSourceName($user['authsource']);
                $userObject->setCreatedAt(new \DateTime('now'));
                $userObject->setUpdatedAt(new \DateTime('now'));
                $userObject->setSendConfirmCount(0);

                $this->userStorage->getDefaultAuth->save($userObject);
            }

                $userObject->setDispatcher(new EventDispatcher());
                $userfsm = UserFSM::getMachine($userObject);

                if(!$userfsm->can(UserFSM::TRANSITION_LOGIN)) {
                    throw new \Exception("Action not allowed on state", RetCode::ACTION_NOT_ALLOWED);
                }
                else{
                    // Login with wrong password
                    $user = $userfsm->getObject();
                    if($user instanceof UserObject){
                        $user-save>setLoginFailedCount($user->getLoginFailedCount() + 1);
                    }
                }
                $userfsm->apply('login');
                $this->userStorage->save($userfsm->getObject());
                return true;
            }
        throw new LoginFailed("Login failed");
    }

    public function modify($uid, $kv = array()){
        if(is_null($uid)) return false;

        $user = $this->userStorage->loadUser($uid);
        if(empty($user)) return false;

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
        if(empty($user)) return false;

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
        if(empty($user)) return false;

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
        if(empty($user)) return false;

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
        if(empty($user)) return false;

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
        if(empty($user)) return false;

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
        if(empty($user)) return false;

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

    public function deleteUser($uid){
        $user = $this->userStorage->loadUser($uid);
        if(empty($user)) return false;

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
