<?php

use Vuba\AuthN;
require '../src/AuthN.php';
require '../vendor/autoload.php';

class AuthNTest extends \PHPUnit\Framework\TestCase
{
    public $userObject;
    public $userFSM;
    public $em;

    public function setup(){

    }

    public function testConfig(){
        $this->setup();
        $confService = new AuthN\Service\ConfServiceYaml(__DIR__.'/../config/config.yml');
        $authn = new Vuba\AuthN\AuthN($confService);

        $username = 'test5';
        $password = 'password';
        $newpw = 'P@ssw0rd';
        $activationCode = '86v7l4';

        $authn->deletUser($username);

        $this->assertTrue($authn->register($username));
        var_dump($authn->searchUser(array('activation_code' => '86v7l4')));
        $this->assertNotNull($authn->searchUser(array('activation_code' => '86v7l4')));
        $this->assertFalse($authn->register($username));

        $this->assertTrue($authn->reSend($username));
        $this->assertTrue($authn->reSend($username));
        $this->assertTrue($authn->reSend($username));
        $this->assertFalse($authn->reSend($username));
        $this->assertFalse($authn->reSend($username));
        $this->assertFalse($authn->reSend($username));

        $this->assertTrue($authn->confirm($username, $password, $activationCode));

        $this->assertTrue($authn->login($username,$password));
        $this->assertFalse($authn->login($username,$newpw));
        $this->assertFalse($authn->login($username,'Password'));
        $this->assertTrue($authn->resetpw($username, $password, 'P@ssw0rd'));
        $this->assertFalse($authn->login($username,'Password'));
        $this->assertFalse($authn->login($username,'Password\' {sdf)(}dsf" µ£µ°30927_-"à\ç=àµM <php? echo "test"; ?> ?>'));
        $this->assertTrue($authn->login($username,'P@ssw0rd'));
        $this->assertTrue($authn->lock($username));
        $this->assertFalse($authn->login($username,$password));
        $this->assertFalse($authn->register($username));
        $this->assertFalse($authn->register($username));
        $this->assertTrue($authn->unlock($username));
        $this->assertTrue($authn->login($username,$newpw));

        $this->assertTrue($authn->login($username,$newpw));
        $this->assertTrue($authn->login($username,$newpw));
        $this->assertTrue($authn->login($username,$newpw));
        $this->assertTrue($authn->login($username,$newpw));
        $this->assertTrue($authn->login($username,$newpw));
        $this->assertTrue($authn->login($username,$newpw));
        $this->assertTrue($authn->login($username,$newpw));

        $authn->modify($username, array(
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
        ));
        $authn->modify($username, array(
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
        ));
        $authn->modify($username, array(
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
        ));
        $authn->modify($username, array(
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
        ));
        $authn->modify($username, array(
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
        ));
        $authn->modify($username, array(
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
        ));
        $authn->modify($username, array(
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
        ));

        $this->assertTrue($authn->forgotpw($username));
        $this->assertTrue($authn->reSendForgotpw($username));
        $this->assertTrue($authn->reSendForgotpw($username));
        $this->assertTrue($authn->reSendForgotpw($username));

        $this->assertFalse($authn->reSendForgotpw($username));
        $this->assertFalse($authn->reSendForgotpw($username));
        $this->assertFalse($authn->reSendForgotpw($username));
        $this->assertFalse($authn->reSendForgotpw($username));

        $this->assertFalse($authn->login($username, $newpw));
        $this->assertTrue($authn->confirm($username,$newpw, $activationCode));
        $this->assertTrue($authn->login($username, $newpw));
        $this->assertTrue($authn->login($username, $newpw));
        $this->assertTrue($authn->login($username, $newpw));
        $this->assertTrue($authn->login($username, $newpw));
        $this->assertTrue($authn->login($username, $newpw));
        $this->assertTrue($authn->login($username, $newpw));
        $this->assertTrue($authn->resetpw($username, $newpw, $password));
        $this->assertTrue($authn->login($username,$password));
        $this->assertTrue($authn->login($username,$password));
        $this->assertTrue($authn->login($username,$password));
        $this->assertTrue($authn->login($username,$password));
        $this->assertTrue($authn->login($username,$password));

        //$authn->deletUser($username);
        /*  */
    }
}

