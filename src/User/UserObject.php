<?php

namespace Vuba\AuthN\User;

use Symfony\Component\EventDispatcher\Event;
use Finite\StatefulInterface;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\Exception\UnsatisfiedDependencyException;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;


class UserObject implements  StatefulInterface
{
    /**
     *
     */
    protected $dispatcher;


    /**
     * @var string
     */
    private $uuid;

    /**
     * @var string
     */
    private $extuid;

    /**
     * @var string
     */
    private $auth_source_name;

    /**
     * @var string
     */
    private $sub;

    /**
     * @var string
     */
    private $name;

    /**
     * @var string
     */
    private $given_name;

    /**
     * @var string
     */
    private $family_name;

    /**
     * @var string
     */
    private $middle_name;

    /**
     * @var string
     */
    private $nickname;

    /**
     * @var string
     */
    private $preferred_username;

    /**
     * @var string
     */
    private $profile;

    /**
     * @var string
     */
    private $email;

    /**
     * @var string
     */
    private $email_verified;

    /**
     * @var integer
     */
    private $gender = 0;

    /**
     * @var string
     */
    private $birthdate;

    /**
     * @var string
     */
    private $zoneinfo;

    /**
     * @var string
     */
    private $locale;

    /**
     * @var string
     */
    private $phone_number;

    /**
     * @var string
     */
    private $address;

    /**
     * @var string
     */
    private $updated_at;

    /**
     * @var string
     */
    private $roles;

    /**
     * @var string
     */
    private $state;

    /**
     * @var string
     */
    private $lastlogon;

    /**
     * @var string
     */
    private $created_at;

    /**
     * @var integer
     */
    private $logon_count = 0;

    /**
     * @var integer
     */
    private $num_activation_code = 0;

    /**
     * @var integer
     */
    private $activation_code_lifetime = 17280;

    /**
     * @var integer
     */
    private $lock_time = 0;


    public function getDispatcher(){
        return $this->dispatcher;
    }

    public function setDispatcher($dispatcher){
        $this->dispatcher = $dispatcher;
    }
    /**
     * Gets the object state.
     *
     * @return string
     */
    public function getFiniteState()
    {
        return $this->getState();
    }

    /**
     * Sets the object state.
     *
     * @param string $state
     */
    public function setFiniteState($state)
    {
        $this->setState($state);
    }

    /**
     * Set uuid
     *
     * @param string $uuid
     *
     * @return UserObject
     */
    public function setUuid($uuid)
    {
        $this->uuid = $uuid;

        return $this;
    }

    /**
     * Get uuid
     *
     * @return string
     */
    public function getUuid()
    {
        return $this->uuid;
    }

    /**
     * Set extuid
     *
     * @param string $extuid
     *
     * @return UserObject
     */
    public function setExtuid($extuid)
    {
        $this->extuid = $extuid;

        return $this;
    }

    /**
     * Get extuid
     *
     * @return string
     */
    public function getExtuid()
    {
        return $this->extuid;
    }

    /**
     * Set authSourceName
     *
     * @param string $authSourceName
     *
     * @return UserObject
     */
    public function setAuthSourceName($authSourceName)
    {
        $this->auth_source_name = $authSourceName;

        return $this;
    }

    /**
     * Get authSourceName
     *
     * @return string
     */
    public function getAuthSourceName()
    {
        return $this->auth_source_name;
    }

    /**
     * Set sub
     *
     * @param string $sub
     *
     * @return UserObject
     */
    public function setSub($sub)
    {
        $this->sub = $sub;

        return $this;
    }

    /**
     * Get sub
     *
     * @return string
     */
    public function getSub()
    {
        return $this->sub;
    }

    /**
     * Set name
     *
     * @param string $name
     *
     * @return UserObject
     */
    public function setName($name)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Set givenName
     *
     * @param string $givenName
     *
     * @return UserObject
     */
    public function setGivenName($givenName)
    {
        $this->given_name = $givenName;

        return $this;
    }

    /**
     * Get givenName
     *
     * @return string
     */
    public function getGivenName()
    {
        return $this->given_name;
    }

    /**
     * Set familyName
     *
     * @param string $familyName
     *
     * @return UserObject
     */
    public function setFamilyName($familyName)
    {
        $this->family_name = $familyName;

        return $this;
    }

    /**
     * Get familyName
     *
     * @return string
     */
    public function getFamilyName()
    {
        return $this->family_name;
    }

    /**
     * Set middleName
     *
     * @param string $middleName
     *
     * @return UserObject
     */
    public function setMiddleName($middleName)
    {
        $this->middle_name = $middleName;

        return $this;
    }

    /**
     * Get middleName
     *
     * @return string
     */
    public function getMiddleName()
    {
        return $this->middle_name;
    }

    /**
     * Set nickname
     *
     * @param string $nickname
     *
     * @return UserObject
     */
    public function setNickname($nickname)
    {
        $this->nickname = $nickname;

        return $this;
    }

    /**
     * Get nickname
     *
     * @return string
     */
    public function getNickname()
    {
        return $this->nickname;
    }

    /**
     * Set preferredUsername
     *
     * @param string $preferredUsername
     *
     * @return UserObject
     */
    public function setPreferredUsername($preferredUsername)
    {
        $this->preferred_username = $preferredUsername;

        return $this;
    }

    /**
     * Get preferredUsername
     *
     * @return string
     */
    public function getPreferredUsername()
    {
        return $this->preferred_username;
    }

    /**
     * Set profile
     *
     * @param string $profile
     *
     * @return UserObject
     */
    public function setProfile($profile)
    {
        $this->profile = $profile;

        return $this;
    }

    /**
     * Get profile
     *
     * @return string
     */
    public function getProfile()
    {
        return $this->profile;
    }

    /**
     * Set email
     *
     * @param string $email
     *
     * @return UserObject
     */
    public function setEmail($email)
    {
        $this->email = $email;

        return $this;
    }

    /**
     * Get email
     *
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * Set emailVerified
     *
     * @param string $emailVerified
     *
     * @return UserObject
     */
    public function setEmailVerified($emailVerified)
    {
        $this->email_verified = $emailVerified;

        return $this;
    }

    /**
     * Get emailVerified
     *
     * @return string
     */
    public function getEmailVerified()
    {
        return $this->email_verified;
    }

    /**
     * Set gender
     *
     * @param integer $gender
     *
     * @return UserObject
     */
    public function setGender($gender)
    {
        $this->gender = $gender;

        return $this;
    }

    /**
     * Get gender
     *
     * @return integer
     */
    public function getGender()
    {
        return $this->gender;
    }

    /**
     * Set birthdate
     *
     * @param string $birthdate
     *
     * @return UserObject
     */
    public function setBirthdate($birthdate)
    {
        $this->birthdate = $birthdate;

        return $this;
    }

    /**
     * Get birthdate
     *
     * @return string
     */
    public function getBirthdate()
    {
        return $this->birthdate;
    }

    /**
     * Set zoneinfo
     *
     * @param string $zoneinfo
     *
     * @return UserObject
     */
    public function setZoneinfo($zoneinfo)
    {
        $this->zoneinfo = $zoneinfo;

        return $this;
    }

    /**
     * Get zoneinfo
     *
     * @return string
     */
    public function getZoneinfo()
    {
        return $this->zoneinfo;
    }

    /**
     * Set locale
     *
     * @param string $locale
     *
     * @return UserObject
     */
    public function setLocale($locale)
    {
        $this->locale = $locale;

        return $this;
    }

    /**
     * Get locale
     *
     * @return string
     */
    public function getLocale()
    {
        return $this->locale;
    }

    /**
     * Set phoneNumber
     *
     * @param string $phoneNumber
     *
     * @return UserObject
     */
    public function setPhoneNumber($phoneNumber)
    {
        $this->phone_number = $phoneNumber;

        return $this;
    }

    /**
     * Get phoneNumber
     *
     * @return string
     */
    public function getPhoneNumber()
    {
        return $this->phone_number;
    }

    /**
     * Set address
     *
     * @param string $address
     *
     * @return UserObject
     */
    public function setAddress($address)
    {
        $this->address = $address;

        return $this;
    }

    /**
     * Get address
     *
     * @return string
     */
    public function getAddress()
    {
        return $this->address;
    }

    /**
     * Set updatedAt
     *
     * @param string $updatedAt
     *
     * @return UserObject
     */
    public function setUpdatedAt($updatedAt)
    {
        $this->updated_at = $updatedAt;

        return $this;
    }

    /**
     * Get updatedAt
     *
     * @return string
     */
    public function getUpdatedAt()
    {
        return $this->updated_at;
    }

    /**
     * Set roles
     *
     * @param string $roles
     *
     * @return UserObject
     */
    public function setRoles($roles)
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * Get roles
     *
     * @return string
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * Set state
     *
     * @param string $state
     *
     * @return UserObject
     */
    public function setState($state)
    {
        $this->state = $state;

        return $this;
    }

    /**
     * Get state
     *
     * @return string
     */
    public function getState()
    {
        return $this->state;
    }

    /**
     * Set lastlogon
     *
     * @param string $lastlogon
     *
     * @return UserObject
     */
    public function setLastlogon($lastlogon)
    {
        $this->lastlogon = $lastlogon;

        return $this;
    }

    /**
     * Get lastlogon
     *
     * @return string
     */
    public function getLastlogon()
    {
        return $this->lastlogon;
    }

    /**
     * Set logonCount
     *
     * @param integer $logonCount
     *
     * @return UserObject
     */
    public function setLogonCount($logonCount)
    {
        $this->logon_count = $logonCount;

        return $this;
    }

    /**
     * Get logonCount
     *
     * @return integer
     */
    public function getLogonCount()
    {
        return $this->logon_count;
    }

    /**
     * Set numActivationCode
     *
     * @param integer $numActivationCode
     *
     * @return UserObject
     */
    public function setNumActivationCode($numActivationCode)
    {
        $this->num_activation_code = $numActivationCode;

        return $this;
    }

    /**
     * Get numActivationCode
     *
     * @return integer
     */
    public function getNumActivationCode()
    {
        return $this->num_activation_code;
    }

    /**
     * Set activationCodeLifetime
     *
     * @param integer $activationCodeLifetime
     *
     * @return UserObject
     */
    public function setActivationCodeLifetime($activationCodeLifetime)
    {
        $this->activation_code_lifetime = $activationCodeLifetime;

        return $this;
    }

    /**
     * Get activationCodeLifetime
     *
     * @return integer
     */
    public function getActivationCodeLifetime()
    {
        return $this->activation_code_lifetime;
    }

    /**
     * Set lockTime
     *
     * @param integer $lockTime
     *
     * @return UserObject
     */
    public function setLockTime($lockTime)
    {
        $this->lock_time = $lockTime;

        return $this;
    }

    /**
     * Get lockTime
     *
     * @return integer
     */
    public function getLockTime()
    {
        return $this->lock_time;
    }

    public static function calculeUuid($extUid, $authSourceName){
            return Uuid::uuid5(Uuid::NAMESPACE_OID, $authSourceName.$extUid)->toString();
    }

    public function setCreatedAt($time){
        $this->created_at = $time;
    }

    public function getCreatedAt(){
        return $this->created_at;
    }


    /**
     * @var integer
     */
    private $send_confirm_count = 0;

    /**
     * @var integer
     */
    private $forget_pw_count = 0;


    /**
     * Set sendConfirmCount
     *
     * @param integer $sendConfirmCount
     *
     * @return UserObject
     */
    public function setSendConfirmCount($sendConfirmCount)
    {
        $this->send_confirm_count = $sendConfirmCount;

        return $this;
    }

    /**
     * Get sendConfirmCount
     *
     * @return integer
     */
    public function getSendConfirmCount()
    {
        return $this->send_confirm_count;
    }

    /**
     * Set forgetPwCount
     *
     * @param integer $forgetPwCount
     *
     * @return UserObject
     */
    public function setForgetPwCount($forgetPwCount)
    {
        $this->forget_pw_count = $forgetPwCount;

        return $this;
    }

    /**
     * Get forgetPwCount
     *
     * @return integer
     */
    public function getForgetPwCount()
    {
        return $this->forget_pw_count;
    }

    /**
     * @var string
     */
    private $preferred_lang;

    /**
     * @var string
     */
    private $preferred_theme;


    /**
     * Set preferredLang
     *
     * @param string $preferredLang
     *
     * @return UserObject
     */
    public function setPreferredLang($preferredLang)
    {
        $this->preferred_lang = $preferredLang;

        return $this;
    }

    /**
     * Get preferredLang
     *
     * @return string
     */
    public function getPreferredLang()
    {
        return $this->preferred_lang;
    }

    /**
     * Set preferredTheme
     *
     * @param string $preferredTheme
     *
     * @return UserObject
     */
    public function setPreferredTheme($preferredTheme)
    {
        $this->preferred_theme = $preferredTheme;

        return $this;
    }

    /**
     * Get preferredTheme
     *
     * @return string
     */
    public function getPreferredTheme()
    {
        return $this->preferred_theme;
    }

    /**
     * @var string
     */
    private $activation_code;


    /**
     * Set activationCode
     *
     * @param string $activationCode
     *
     * @return UserObject
     */
    public function setActivationCode($activationCode)
    {
        $this->activation_code = $activationCode;

        return $this;
    }

    /**
     * Get activationCode
     *
     * @return string
     */
    public function getActivationCode()
    {
        return $this->activation_code;
    }

    /**
     * @var integer
     */
    private $login_failed_count = 0;


    /**
     * Set loginFailedCount
     *
     * @param integer $loginFailedCount
     *
     * @return UserObject
     */
    public function setLoginFailedCount($loginFailedCount)
    {
        $this->login_failed_count = $loginFailedCount;

        return $this;
    }

    /**
     * Get loginFailedCount
     *
     * @return integer
     */
    public function getLoginFailedCount()
    {
        return $this->login_failed_count;
    }


    private $claims;

    /**
     * Set claims
     *
     * @param string $claims
     *
     * @return UserObject
     */
    public function setClaims($claims)
    {
        $this->claims = $claims;

        return $this;
    }

    /**
     * Get claims
     *
     * @return string
     */
    public function getClaims()
    {
        return $this->claims;
    }
}
