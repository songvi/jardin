<?php

use Vuba\AuthN\AuthN;
use Vuba\AuthN\Service\ConfServiceYaml;
use Vuba\AuthN\Exception\ActivationKeyInvalid;
use Psr\Log\AbstractLogger;
use \Vuba\AuthN\Exception\RetCode;

require '../src/AuthN.php';
require '../vendor/autoload.php';


class AuthNTest extends \PHPUnit\Framework\TestCase
{
    public static $authn;
    public static $user;
    public static $logger;
    public static $context;

    public static function setUpBeforeClass()
    {
        $confService = new ConfServiceYaml(__DIR__ . '/../config/config.yml');
        self::$authn = new AuthN($confService);
        self::$user['username'] = 'test';
        self::$user['password'] = 'password';
        self::$user['username2'] = 'test2';
        self::$user['password2'] = 'password2';
        self::$user['newpw'] = 'P@ssw0rd';
        self::$logger = new logger();
        self::$context = array();
    }

    protected function setUp()
    {
        self::$authn->register(self::$user['username'], self::$context, self::$logger);
        $user = self::$authn->loadUser(self::$user['username'], self::$context, self::$logger);
        if ($user instanceof \Vuba\AuthN\User\UserObject) {
            $activationCode = $user->getActivationCode();
        }
        self::$authn->confirm(self::$user['username'], self::$user['password'], $activationCode, self::$context, self::$logger);
    }

    public function testRegistration()
    {
        $this->assertTrue(self::$authn->register(self::$user['username2'], self::$context, self::$logger));
        $this->expectExceptionCode(RetCode::USER_ALREADY_EXISTED);
        self::$authn->register(self::$user['username2'], self::$context, self::$logger);

        $this->assertTrue(self::$authn->reSend(self::$user['username2'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->reSend(self::$user['username2'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->reSend(self::$user['username2'], self::$context, self::$logger));
        $this->expectExceptionCode(\Vuba\AuthN\Exception\RetCode::ACTION_NOT_ALLOWED);
        $this->assertFalse(self::$authn->reSend(self::$user['username2'], self::$context, self::$logger));
        $this->expectExceptionCode(\Vuba\AuthN\Exception\RetCode::ACTION_NOT_ALLOWED);
        $this->assertFalse(self::$authn->reSend(self::$user['username2'], self::$context, self::$logger));

        $activationCode = "sldfjslkdfj";
        $this->expectExceptionCode(RetCode::ACTIVATION_KEY_INVALID);
        self::$authn->confirm(self::$user['username2'], self::$user['password2'], $activationCode, self::$context, self::$logger);

        $user = self::$authn->loadUser(self::$user['username2'], self::$context, self::$logger);
        if ($user instanceof \Vuba\AuthN\User\UserObject) {
            $activationCode = $user->getActivationCode();
        }
        $this->assertTrue(self::$authn->confirm(self::$user['username2'], self::$user['password2'], $activationCode, self::$context, self::$logger));
    }

    public function testLogin()
    {
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));

        $user = self::$authn->loadUser(self::$user['username'], self::$context, self::$logger);
        $this->assertEquals(9, $user->getLogonCount());
        $this->assertNotEquals(8, $user->getLogonCount());

        self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger);
        $user = self::$authn->loadUser(self::$user['username'], self::$context, self::$logger);
        $this->assertEquals(10, $user->getLogonCount());

    }

    public function testLoginFailed(){
        $this->expectException(Vuba\AuthN\Exception\LoginFailedException::class);
        self::$authn->login(self::$user['username'], "sfssqfsfsdfqdfsqf", self::$context, self::$logger);
    }

    public function testLoginFailedCount(){
        try {
            self::$authn->login(self::$user['username'], "sfssqfsfsdfqdfsqf", self::$context, self::$logger);
        }
        catch(\Exception $e){}

        try {
            self::$authn->login(self::$user['username'], "sfsé§MLI30740937Plfsjfsjfmqdfsqf", self::$context, self::$logger);
        }
        catch(\Exception $e){}
        $user = self::$authn->loadUser(self::$user['username'], self::$context, self::$logger);
        $this->assertEquals(2, $user->getLoginFailedCount());
    }

    public function testResetPassword()
    {
        //$this->testConfirm();
        $this->assertTrue(self::$authn->resetpw(self::$user['username'], self::$user['password'], "password2", self::$context, self::$logger));
        $this->assertFalse(self::$authn->resetpw(self::$user['username'], self::$user['password'], "password", self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password2'], self::$context, self::$logger));
    }

    public function testLockUser(){
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->lock(self::$user['username'], self::$context, self::$logger));
        $this->expectExceptionCode(RetCode::ACTION_NOT_ALLOWED);
        self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger);
    }

    public function testUnlock(){
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->lock(self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->unlock(self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['password'], self::$context, self::$logger));
    }

    public function testEdit(){
        self::$authn->modify(self::$user['username'], array(
            'sub' => 'Sub',
            'name' => 'Name',
            'given_name' => 'Given Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-02 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '0123456789',
            'address' => 'Address at 45 avenue du monde'
        ), self::$context, self::$logger);

        $user = self::$authn->loadUser(self::$user['username'], self::$context, self::$logger);
        if($user instanceof \Vuba\AuthN\User\UserObject){
            $this->assertEquals($user->getSub(), 'Sub');
            $this->assertEquals($user->getName(), 'Name');
            $this->assertEquals($user->getGivenName(), 'Given Name');
            $this->assertEquals($user->getFamilyName(), 'Family Name');
            $this->assertEquals($user->getMiddleName(), 'Middle Name');
            $this->assertEquals($user->getNickname(), 'Nick Name');
            $this->assertEquals($user->getPreferredUsername(), 'Preferred Username');
            $this->assertEquals($user->getProfile(), 'Profile');
            $this->assertEquals($user->getEmail(), 'Email@gmail.com');
            $this->assertEquals($user->getGender(), 1);
            $this->assertEquals($user->getZoneinfo(), 'ZoneInfo');
            $this->assertEquals($user->getLocale(), 'Locale');
            $this->assertEquals($user->getPhoneNumber(), '0123456789');
            $this->assertEquals($user->getAddress(), 'Address at 45 avenue du monde');
        }

        self::$authn->modify(self::$user['username'], array(
            'sub' => 'SubSubSub',
            'name' => 'NameNameName',
            'given_name' => 'Given NameGiven Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-02 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '0123456789',
            'address' => 'Address at 45 avenue du monde'
        ), self::$context, self::$logger);

        $user = self::$authn->loadUser(self::$user['username'], self::$context, self::$logger);
        if($user instanceof \Vuba\AuthN\User\UserObject){
            $this->assertEquals($user->getSub(), 'SubSubSub');
            $this->assertEquals($user->getName(), 'NameNameName');
            $this->assertEquals($user->getGivenName(), 'Given NameGiven Name');
            $this->assertEquals($user->getFamilyName(), 'Family Name');
            $this->assertEquals($user->getMiddleName(), 'Middle Name');
            $this->assertEquals($user->getNickname(), 'Nick Name');
            $this->assertEquals($user->getPreferredUsername(), 'Preferred Username');
            $this->assertEquals($user->getProfile(), 'Profile');
            $this->assertEquals($user->getEmail(), 'Email@gmail.com');
            $this->assertEquals($user->getGender(), 1);
            $this->assertEquals($user->getZoneinfo(), 'ZoneInfo');
            $this->assertEquals($user->getLocale(), 'Locale');
            $this->assertEquals($user->getPhoneNumber(), '0123456789');
            $this->assertEquals($user->getAddress(), 'Address at 45 avenue du monde');
        }

    }
    /*
    public function testother(){
       // $this->expectException(ActivationKeyInvalid::class);
        self::$authn->modify(self::$user['username'], array(
            'sub' => 'Sub',
            'name' => 'Name',
            'given_name' => 'Given Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-02 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '0123456789',
            'address' => 'Address at 45 avenue du monde'
        ), self::$context, self::$logger);
        self::$authn->modify(self::$user['username'], array(
            'sub' => 'Sub',
            'name' => 'Name',
            'given_name' => 'Given Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-02 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '0123456789',
            'address' => 'Address at 45 avenue du monde'
        ), self::$context, self::$logger);
        self::$authn->modify(self::$user['username'], array(
            'sub' => 'Sub',
            'name' => 'Name',
            'given_name' => 'Given Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-02 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '0123456789',
            'address' => 'Address at 45 avenue du monde'
        ), self::$context, self::$logger);
        self::$authn->modify(self::$user['username'], array(
            'sub' => 'Sub',
            'name' => 'Name',
            'given_name' => 'Given Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-02 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '0123456789',
            'address' => 'Address at 45 avenue du monde'
        ), self::$context, self::$logger);
        self::$authn->modify(self::$user['username'], array(
            'sub' => 'Sub',
            'name' => 'Name',
            'given_name' => 'Given Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-02 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '0123456789',
            'address' => 'Address at 45 avenue du monde'
        ), self::$context, self::$logger);
        self::$authn->modify(self::$user['username'], array(
            'sub' => 'Sub',
            'name' => 'Name',
            'given_name' => 'Given Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-02 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '0123456789',
            'address' => 'Address at 45 avenue du monde'
        ), self::$context, self::$logger);
        self::$authn->modify(self::$user['username'], array(
            'sub' => 'Sub',
            'name' => 'Name',
            'given_name' => 'Given Name',
            'family_name' => 'Family Name',
            'middle_name' => 'Middle Name2',
            'nickname' => 'Nick Name',
            'preferred_username' => 'Preferred Username2',
            'profile' => 'Profile',
            'email' => 'Email@gmail.com',
            'email_verified' => 'Email@gmail.com',
            'gender' => '1',
            'birthdate' => new \DateTime('2000-01-03 00:00:00'),
            'zoneinfo' => 'ZoneInfo',
            'locale' => 'Locale',
            'phone_number' => '012345678912',
            'address' => 'Address at 45 avennue du monde'
        ), self::$context, self::$logger);

        $this->assertTrue(self::$authn->forgotpw(self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->reSendForgotpw(self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->reSendForgotpw(self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->reSendForgotpw(self::$user['username'], self::$context, self::$logger));

        $this->assertFalse(self::$authn->reSendForgotpw(self::$user['username'], self::$context, self::$logger));
        $this->assertFalse(self::$authn->reSendForgotpw(self::$user['username'], self::$context, self::$logger));
        $this->assertFalse(self::$authn->reSendForgotpw(self::$user['username'], self::$context, self::$logger));
        $this->assertFalse(self::$authn->reSendForgotpw(self::$user['username'], self::$context, self::$logger));

        $this->assertFalse(self::$authn->login(self::$user['username'], self::$user['newpw'], self::$context, self::$logger));
        //$this->assertTrue(self::$authn->confirm(self::$user['username'], $activationCode,self::$user['newpw']));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['newpw'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['newpw'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['newpw'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['newpw'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['newpw'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'], self::$user['newpw'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->resetpw(self::$user['username'], self::$user['newpw'], self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'],self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'],self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'],self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'],self::$user['username'], self::$context, self::$logger));
        $this->assertTrue(self::$authn->login(self::$user['username'],self::$user['username'], self::$context, self::$logger));

        $this->assertTrue(self::$authn->deleteUser(self::$user['username'], self::$context, self::$logger));
    }
    */

    public function tearDown()
    {
        self::$authn->deleteUser(self::$user['username'], self::$context, self::$logger);
        try {
            self::$authn->deleteUser(self::$user['username2'], self::$context, self::$logger);
        }
        catch(\Exception $e){}
    }

    public function tearDownBeforeClass()
    {
    }
}

class logger extends AbstractLogger{

    /**
     * Logs with an arbitrary level.
     *
     * @param mixed $level
     * @param string $message
     * @param array $context
     *
     * @return void
     */
    public function log($level, $message, array $context = array())
    {

    }
}