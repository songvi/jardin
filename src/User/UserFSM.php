<?php

namespace Vuba\AuthN\User;

use Finite\Event\TransitionEvent;
use Finite\StatefulInterface;
use Finite\StateMachine\StateMachine;
use Finite\State\State;
use Finite\State\StateInterface;
use Finite\Transition\Transition;
use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\Validator\Constraints\DateTime;
use Vuba\AuthN\Service\IConfService;

class UserFSM
{
    const USER_STATE_INIT = 'start';
    const USER_WAIT_FOR_CONFIRMATION = 'waitforconfirm';
    const USER_STATE_NORMAL = 'normal';
    const USER_STATE_LOCK = 'locked';
    const USER_STATE_CLOSED = 'closed';

    const TRANSITION_REGISTER = 'register';
    const TRANSITION_RESEND = 'resend';
    const TRANSITION_CONFIRM = 'confirm';
    const TRANSITION_RESETPASSWORD = 'resetpw';
    const TRANSITION_FORGOTPW = 'forgotpw';
    const TRANSITION_RESEND_FORGOTPW = 'resendforgotpw';
    const TRANSITION_MODIFY = 'modify';
    const TRANSITION_LOGIN = 'login';
    const TRANSITION_ADMINLOCK = 'adminlock';
    const TRANSITION_LOCK = 'lock';
    const TRANSITION_UNLOCK = 'unlock';
    const TRANSITION_CLOSE = 'close';

    public $dispatcher;

    public static function getMachine(StatefulInterface $userObject)
    {
        $sm = new StateMachine();

        // Define states
        $initState = new State(UserFSM::USER_STATE_INIT, StateInterface::TYPE_INITIAL);
        $initState->setProperties(array(
            'actions' => 'register'
        ));

        $sm->addState($initState);

        $sm->addState(UserFSM::USER_WAIT_FOR_CONFIRMATION);

        $normalState = new State(UserFSM::USER_STATE_NORMAL, StateInterface::TYPE_NORMAL);
        $normalState->setProperties(array(
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
            'preferred_theme',
            'preferred_lang',
        ));
        $sm->addState($normalState);

        $sm->addState(new State(UserFSM::USER_STATE_LOCK, StateInterface::TYPE_NORMAL));
        $sm->addState(new State(UserFSM::USER_STATE_CLOSED, StateInterface::TYPE_FINAL));


        // Define transitions
        $sm->addTransition(new Transition(UserFSM::TRANSITION_REGISTER,
            UserFSM::USER_STATE_INIT,
            UserFSM::USER_WAIT_FOR_CONFIRMATION,
            array(__NAMESPACE__ . '\UserFSM', 'gRegister')
        ));

        // user has a limit times to do the confirmation request
        $sm->addTransition(new Transition(UserFSM::TRANSITION_RESEND,
            UserFSM::USER_WAIT_FOR_CONFIRMATION,
            UserFSM::USER_WAIT_FOR_CONFIRMATION,
            array(__NAMESPACE__ . '\UserFSM', 'gReSend')
        ));


        $sm->addTransition(new Transition(UserFSM::TRANSITION_CONFIRM,
            UserFSM::USER_WAIT_FOR_CONFIRMATION,
            UserFSM::USER_STATE_NORMAL,
            array(__NAMESPACE__ . '\UserFSM', 'gConfirm')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_LOGIN,
            UserFSM::USER_STATE_NORMAL,
            UserFSM::USER_STATE_NORMAL,
            array(__NAMESPACE__ . '\UserFSM', 'gLogin')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_MODIFY,
            UserFSM::USER_STATE_NORMAL,
            UserFSM::USER_STATE_NORMAL,
            array(__NAMESPACE__ . '\UserFSM', 'gModify')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_RESETPASSWORD,
            UserFSM::USER_STATE_NORMAL,
            UserFSM::USER_STATE_NORMAL,
            array(__NAMESPACE__ . '\UserFSM', 'gResetPW')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_FORGOTPW,
            UserFSM::USER_STATE_NORMAL,
            UserFSM::USER_WAIT_FOR_CONFIRMATION,
            array(__NAMESPACE__ . '\UserFSM', 'gForgotPW')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_RESEND_FORGOTPW,
            UserFSM::USER_WAIT_FOR_CONFIRMATION,
            UserFSM::USER_WAIT_FOR_CONFIRMATION,
            array(__NAMESPACE__ . '\UserFSM', 'gReSendForgotPW')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_LOCK,
            UserFSM::USER_STATE_NORMAL,
            UserFSM::USER_STATE_LOCK,
            array(__NAMESPACE__ . '\UserFSM', 'gLock')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_ADMINLOCK,
            UserFSM::USER_STATE_NORMAL,
            UserFSM::USER_STATE_LOCK,
            array(__NAMESPACE__ . '\UserFSM', 'gAdminLock')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_UNLOCK,
            UserFSM::USER_STATE_LOCK,
            UserFSM::USER_STATE_NORMAL,
            array(__NAMESPACE__ . '\UserFSM', 'gUnlock')
        ));

        $sm->addTransition(new Transition(UserFSM::TRANSITION_CLOSE,
            UserFSM::USER_STATE_LOCK,
            UserFSM::USER_STATE_CLOSED,
            array(__NAMESPACE__ . '\UserFSM', 'gClose')
        ));


        // Initialize
        $sm->setObject($userObject);
        if ($userObject instanceof UserObject) {
            $sm->setDispatcher($userObject->getDispatcher());
        }

        $sm->initialize();

        /**
         * Add listeners
         */
        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_REGISTER,
            array(__NAMESPACE__ . '\UserFSM', 'aRegister'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_RESEND,
            array(__NAMESPACE__ . '\UserFSM', 'aReSend'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_CONFIRM,
            array(__NAMESPACE__ . '\UserFSM', 'aConfirm'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_FORGOTPW,
            array(__NAMESPACE__ . '\UserFSM', 'aForgotPW'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_RESEND_FORGOTPW,
            array(__NAMESPACE__ . '\UserFSM', 'aReSendForgotPW'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_RESETPASSWORD,
            array(__NAMESPACE__ . '\UserFSM', 'aResetPW'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_MODIFY,
            array(__NAMESPACE__ . '\UserFSM', 'aModify'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_LOGIN,
            array(__NAMESPACE__ . '\UserFSM', 'aLogin'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_ADMINLOCK,
            array(__NAMESPACE__ . '\UserFSM', 'aAdminLock'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_LOCK,
            array(__NAMESPACE__ . '\UserFSM', 'aLock'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_UNLOCK,
            array(__NAMESPACE__ . '\UserFSM', 'aUnlock'));

        $sm->getDispatcher()->addListener('finite.post_transition.' . UserFSM::TRANSITION_CLOSE,
            array(__NAMESPACE__ . '\UserFSM', 'aClose'));


        return $sm;
    }


    public static function gRegister(StateMachine $sm)
    {
        return true;
    }

    public static function gReSend(StateMachine $sm)
    {
        // send_confirmation_count < = max_allowed
        $user = $sm->getObject();
        if ($user instanceof UserObject) {
            if ($user->getSendConfirmCount() > IConfService::MAX_REQUEST_REGISTER) return false;
        }
        return true;
    }

    public static function gConfirm(StateMachine $sm)
    {
        // send_confirmation_count < = max_allowed
        // Activation code should match
        $user = $sm->getObject();
        if ($user instanceof UserObject) {
            $now = new \DateTime('now');
            if (($now->getTimestamp() - $user->getActivationCodeLifetime()->getTimestamp()) > IConfService::ACTIVATION_CODE_LIFE_TIME) return false;
        }

        return true;
    }

    public static function gResetPW(StateMachine $sm)
    {
        return true;
    }

    public static function gForgotPW(StateMachine $sm)
    {
        $user = $sm->getObject();
        if ($user instanceof UserObject) {
            if (
                $user->getForgetPwCount() > IConfService::MAX_REQUEST_FORGOTPW
            ) return false;
        }
        return true;
    }

    public static function gReSendForgotPW(StateMachine $sm)
    {
        $user = $sm->getObject();
        if ($user instanceof UserObject) {
            if (
                $user->getForgetPwCount() > IConfService::MAX_REQUEST_FORGOTPW
            ) return false;
        }
        return true;
    }

    public static function gModify(StateMachine $sm)
    {
        return true;
    }

    public static function gLogin(StateMachine $sm)
    {
        return true;
    }

    public static function gAdminLock(StateMachine $sm)
    {
        return true;
    }

    public static function gLock(StateMachine $sm)
    {
        return true;
    }

    public static function gUnlock(StateMachine $sm)
    {
        return true;
    }

    public static function gClose(StateMachine $sm)
    {
        return true;
    }

    /**
     * @param Event $event
     */

    public static function aRegister(Event $event)
    {
        // Generate activation code
        // Save activation code
        // Send to user via extuid

        if ($event instanceof TransitionEvent) {
            $userObject = $event->getStateMachine()->getObject();
            if ($userObject instanceof UserObject) {
                $userObject->setCreatedAt(new \DateTime('now'));
                $userObject->setUpdatedAt(new \DateTime('now'));
                $userObject->setActivationCodeLifetime(new \DateTime('now'));
                $userObject->setActivationCode(UserFSM::genActivationCode());
                $userObject->setSendConfirmCount($userObject->getSendConfirmCount() + 1);
            }
        }
    }

    public static function aReSend(Event $event)
    {
        if ($event instanceof TransitionEvent) {
            $userObject = $event->getStateMachine()->getObject();
            if ($userObject instanceof UserObject) {
                $userObject->setUpdatedAt(new \DateTime('now'));
                $userObject->setSendConfirmCount($userObject->getSendConfirmCount() + 1);
            }
        }
    }

    public static function aConfirm(Event $event)
    {
        if ($event instanceof TransitionEvent) {
            $userObject = $event->getStateMachine()->getObject();
            if ($userObject instanceof UserObject) {
                $userObject->setUpdatedAt(new \DateTime('now'));
                $userObject->setSendConfirmCount(0);
            }
        }
    }

    public static function aResetPW(Event $event)
    {
        if ($event instanceof TransitionEvent) {
            $userObject = $event->getStateMachine()->getObject();
            if ($userObject instanceof UserObject) {

            }
        }
    }

    public static function aModify(Event $event)
    {
        if ($event instanceof TransitionEvent) {
            $userObject = $event->getStateMachine()->getObject();
            if ($userObject instanceof UserObject) {
                $userObject->setUpdatedAt(new \DateTime('now'));
            }
        }
    }

    public static function aLogin(Event $event)
    {
        if ($event instanceof TransitionEvent) {
            $userObject = $event->getStateMachine()->getObject();
            if ($userObject instanceof UserObject) {
                $userObject->setLastlogon(new \DateTime('now'));
                $userObject->setLogonCount($userObject->getLogonCount() + 1);
                $userObject->setSendConfirmCount(0);
                $userObject->setLockTime(0);
                $userObject->setForgetPwCount(0);
                $userObject->setLoginFailedCount(0);
            }
        }
    }

    public static function aForgotPW(Event $event)
    {
        if ($event instanceof TransitionEvent) {
            $userObject = $event->getStateMachine()->getObject();
            if ($userObject instanceof UserObject) {
                // TODO
                // Generate activation code
                // Set activation code
                // Set activation code lifetime
                // Send to client by extuid
                // Set forget_pw_count =+ 1
                $userObject->setActivationCode(UserFSM::genActivationCode());
                $userObject->setActivationCodeLifetime(new \DateTime("now"));
                $userObject->setForgetPwCount($userObject->getForgetPwCount() + 1);
            }
        }
    }


    public static function aReSendForgotPW(Event $event)
    {
        if ($event instanceof TransitionEvent) {
            $userObject = $event->getStateMachine()->getObject();
            if ($userObject instanceof UserObject) {
                // TODO
                // Generate activation code
                // Set activation code
                // Set activation code lifetime
                // Send to client by extuid
                // Set forget_pw_count =+ 1
                $userObject->setActivationCode(UserFSM::genActivationCode());
                $userObject->setActivationCodeLifetime(new \DateTime("now"));
                $userObject->setForgetPwCount($userObject->getForgetPwCount() + 1);

                // Send mail
            }
        }
    }

    public static function aAdminLock(Event $event)
    {
        if ($event instanceof TransitionEvent) {

        }
    }

    public static function aLock(Event $event)
    {
        if ($event instanceof TransitionEvent) {

        }
    }

    public static function aUnlock(Event $event)
    {
        if ($event instanceof TransitionEvent) {

        }
    }

    public static function aClose(Event $event)
    {
        if ($event instanceof TransitionEvent) {

        }
    }

    public static function genActivationCode($length = 64)
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        //$characters = '0123456789abcdefghijklmnopqrstuvwxyz';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }
}

