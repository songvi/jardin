<?php

namespace Vuba\AuthN;

use Doctrine\ORM\EntityManager;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Security\Core\User\User;
use Vuba\AuthN\AuthStack\AuthStack;
use Vuba\AuthN\Exception\ActionNotAllowOnStateException;
use Vuba\AuthN\Exception\ActivationKeyInvalid;
use Vuba\AuthN\Exception\ActivationKeyInvalidException;
use Vuba\AuthN\Exception\LoginFailedException;
use Vuba\AuthN\Exception\UserAlreadyExistedException;
use Vuba\AuthN\Exception\UserNotFoundException;
use Psr\Log\LoggerInterface;
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
    private $logger;

    /**
     * @param IConfService $confService
     */
    public function __construct(IConfService $confService)
    {
        $this->authStack = new AuthStack($confService);
        $userStorage = $confService->getUserStorage();
        if (!empty($userStorage) && isset($userStorage['type'])) {
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

    public function register($uid, array $context, LoggerInterface $logger)
    {
        // If user's already existed in auth sql and auth storage
        if ($this->authStack->userExist($uid)) {
            $logger->warning(sprintf("User %s has been existed", $uid), $context);
            throw new UserAlreadyExistedException();
        }

        $user = new UserObject();
        $user->setExtuid($uid);
        $user->setUuid(UserObject::calculeUuid($uid, $this->authStack->getDefaultAuth()->authSourceName));
        $user->setAuthSourceName($this->authStack->getDefaultAuth()->authSourceName);
        $user->setDispatcher(new EventDispatcher());

        $userfsm = UserFSM::getMachine($user);
        if ($userfsm->can(UserFSM::TRANSITION_REGISTER)) {
            $userfsm->apply(UserFSM::TRANSITION_REGISTER);
            $user = $userfsm->getObject();
            // Create user in storage
            // Create user in auth table
            $logger->info(sprintf("User %s has not been existed in storage, create new", $uid), $context);
            return $this->userStorage->save($user) && $this->authStack->getDefaultAuth()->createUser($uid, '');
        }else{
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }
    }

    public function reSend($uid, array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) return false;
        $user = $this->userStorage->loadUser($uid);
        if (empty($user)) throw new UserNotFoundException();

        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        if ($userfsm->can(UserFSM::TRANSITION_RESEND)) {
            $userfsm->apply(UserFSM::TRANSITION_RESEND);
            $this->userStorage->save($userfsm->getObject());
            $logger->info(sprintf("Send activation code to use: %s", $uid), $context);
            return true;
        }else{
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }
    }

    public function confirm($uid, $password, $activationCode, array $context, LoggerInterface $logger)
    {
        if (is_null($password)) return false;
        $user = $this->authStack->userExist($uid);

        if(empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();
        $user = $this->userStorage->loadUser($user['uuid']);
        if (empty($user)) throw new UserNotFoundException();

        if (empty($activationCode)) throw new ActivationKeyInvalidException("Activation key invalid");
        if ($user instanceof UserObject) {
            if ($activationCode !== $user->getActivationCode()) {
                throw new ActivationKeyInvalidException("Activation key invalid");
            }
        }

        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        if ($userfsm->can(UserFSM::TRANSITION_CONFIRM)) {
            $this->authStack->getDefaultAuth()->updatePassword($uid, $password);
            $userfsm->apply(UserFSM::TRANSITION_CONFIRM);
            $this->userStorage->save($userfsm->getObject());
            $logger->info(sprintf("User %s is confirmed correctly", $uid), $context);
            return true;
        }else{
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }
    }

    public function login($uid, $password, array $context, LoggerInterface $logger)
    {
        if (empty($uid) || empty($password)) return false;
        $user = $this->authStack->userExist($uid);
        if (!empty($user)) {
            $userObject = $this->userStorage->loadUser($user['uuid']);
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
                $logger->info(sprintf("Create %s in user storage", $uid), $context);
                $this->userStorage->getDefaultAuth->save($userObject);
            }

            $userObject->setDispatcher(new EventDispatcher());
            $userfsm = UserFSM::getMachine($userObject);

            if ($userfsm->can(UserFSM::TRANSITION_LOGIN)) {
                if($this->authStack->login($uid, $password)) {
                    $userfsm->apply('login');
                    $logger->info(sprintf("User %s logged in successfully", $uid), $context);
                    //$userObject->setLogonCount($userObject->getLogonCount() + 1);
                    $this->userStorage->save($userObject);
                    return true;
                }else
                {
                    // Login with wrong password
                    $user = $userfsm->getObject();
                    if ($user instanceof UserObject) {
                        $user->setLoginFailedCount($user->getLoginFailedCount() + 1);
                        $logger->warning(sprintf("Login failed for user %s", $uid), $context);
                        $this->userStorage->save($user);
                    }
                    throw new LoginFailedException();
                }
            } else {
                throw new ActionNotAllowOnStateException();
            }
        }
        throw new UserNotFoundException();
    }

    public function modify($uid, $kv = array(), array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) return false;
        $user = $this->authStack->userExist($uid);
        if(empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();

        $user = $this->userStorage->loadUser($user['uuid']);
        if (empty($user)) throw new UserNotFoundException();

        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if (!$userfsm->can(UserFSM::TRANSITION_MODIFY)) {
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
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
        if ($user instanceof UserObject) {
            foreach ($allowedAttributes as $key => $value) {
                if (isset($kv[$value])) {
                    switch ($value) {
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
        $logger->info(sprintf("update user %s successfully", $uid), $context);
        return true;
    }

    public function resetpw($uid, $oldpassword, $newpassword, array $context, LoggerInterface $logger)
    {
        if (is_null($uid) ||
            is_null($oldpassword) ||
            is_null($newpassword)
        ) return false;

        $user = $this->authStack->userExist($uid);
        if (empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();

        $user = $this->userStorage->loadUser($user['uuid']);
        if (empty($user)) return false;


        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if (!$userfsm->can(UserFSM::TRANSITION_RESETPASSWORD)) {
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }

        // TODO Check password conform
        if ($this->authStack->getDefaultAuth()->checkPassword($uid, $oldpassword)) {
            $this->authStack->getDefaultAuth()->updatePassword($uid, $newpassword);
            $logger->info(sprintf("User %s changes password successfully", $uid), $context);
            return true;
        }
        return false;
    }

    public function forgotpw($uid, array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) return false;

        $user = $this->authStack->userExist($uid);
        if (empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();

        $user = $this->userStorage->loadUser($user['uuid']);
        if (empty($user)) throw new UserNotFoundException();

        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);

        if (!$userfsm->can(UserFSM::TRANSITION_FORGOTPW)) {
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }

        $userfsm->apply(UserFSM::TRANSITION_FORGOTPW);
        $this->userStorage->save($userfsm->getObject());
        $logger->info(sprintf("User %s requests for forgot password flow", $uid), $context);
        return true;
    }

    public function reSendForgotpw($uid, array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) return false;
        $user = $this->authStack->userExist($uid);
        if (empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();

        $user = $this->userStorage->loadUser($user['uuid']);
        if (empty($user)) throw new UserNotFoundException();
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        if (!$userfsm->can(UserFSM::TRANSITION_RESEND_FORGOTPW)) {
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }
        $userfsm->apply(UserFSM::TRANSITION_RESEND_FORGOTPW);
        $this->userStorage->save($userfsm->getObject());
        $logger->info(sprintf("User %s requests (again) for forgot password flow", $uid), $context);
        return true;
    }

    public function lock($uid, array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) return false;
        $user = $this->authStack->userExist($uid);
        if (empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();
        $user = $this->userStorage->loadUser($user['uuid']);
        if (empty($user)) throw new UserNotFoundException();
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        if (!$userfsm->can(UserFSM::TRANSITION_LOCK)) {
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }
        $userfsm->apply(UserFSM::TRANSITION_LOCK);
        $this->userStorage->save($userfsm->getObject());
        $logger->warning(sprintf("User %s is locked", $uid), $context);
        return true;
    }

    public function unlock($uid, array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) return false;
        $user = $this->authStack->userExist($uid);
        if (empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();
        $user = $this->userStorage->loadUser($user['uuid']);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        if ($userfsm->can(UserFSM::TRANSITION_UNLOCK)) {
            $userfsm->apply(UserFSM::TRANSITION_UNLOCK);
            $this->userStorage->save($userfsm->getObject());
            $logger->info(sprintf("User %s is unlock", $uid), $context);
            return true;
        }
        throw new ActionNotAllowOnStateException();
    }

    public function close($uid, array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) return false;
        $user = $this->authStack->userExist($uid);
        if (empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();
        $user = $this->userStorage->loadUser($user['uuid']);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        if (!$userfsm->can(UserFSM::TRANSITION_CLOSE)) {
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }
        $userfsm->apply(UserFSM::TRANSITION_CLOSE);
        $this->userStorage->save($userfsm->getObject());
        $logger->info(sprintf("User %s is disabled", $uid), $context);
        return true;
    }

    /**
     *
     */
    public function getUserList(array $context, LoggerInterface $logger)
    {

    }

    public function deleteUser($uid, array $context, LoggerInterface $logger)
    {
        $user = $this->authStack->userExist($uid);
        if (empty($user) || !isset($user['authsource'])) throw new UserNotFoundException();
        $user = $this->userStorage->loadUser($user['uuid']);

        if (!$this->authStack->getDefaultAuth()->isExist($uid) || is_null($user)) {
            $logger->error(sprintf("User %s is not allowed to do %s", $uid, "register"), $context);
            throw new ActionNotAllowOnStateException();
        }
        $this->authStack->getDefaultAuth()->delete($uid);
        $this->userStorage->deleteUser($user);
        $logger->warning(sprintf("Delete user %s", $uid), $context);
        return true;
    }

    public function searchUser($criterias = array(), array $context, LoggerInterface $logger)
    {
        $users = $this->userStorage->search($criterias);
        return $users;
    }

    public function loadUser($uid, array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) throw new UserNotFoundException();
        $user = $this->authStack->userExist($uid);
        if(!empty($user)){
            return $this->userStorage->loadUser($user['uuid']);
        }
        return null;
    }

    public function getCurrentState($uid, array $context, LoggerInterface $logger)
    {
        if (is_null($uid)) throw new UserNotFoundException();
        $user = $this->userStorage->loadUser($uid);
        $user->setDispatcher(new EventDispatcher());
        $userfsm = UserFSM::getMachine($user);
        return $userfsm->getCurrentState();
    }
}
