<?php

require '../vendor/autoload.php';
require '../src/AuthStack/AuthMySQL.php';

class UserFSMTest extends \PHPUnit\Framework\TestCase
{
    public $userObject;
    public $userFSM;


    public function setup(){
        $userObject = new \Vuba\AuthN\User\UserObjectState('test', 'mysql');
        $userObject->setState(\Vuba\AuthN\User\UserFSM::USER_STATE_INIT);
        $userObject->setDispatcher(new \Symfony\Component\EventDispatcher\EventDispatcher());
        $this->userFSM = \Vuba\AuthN\User\UserFSM::getMachine($userObject);
        //$this->userFSM->getObject()
        //var_dump($this->userFSM);
    }

    public function testState(){
        $this->setup();

        // State init
        $this->userFSM->getObject()->setState(\Vuba\AuthN\User\UserFSM::USER_STATE_INIT);
        $this->assertTrue($this->userFSM->can('register'));
        $this->assertFalse($this->userFSM->can('resetpw'));
        $this->assertFalse($this->userFSM->can('login'));
        $this->assertTrue($this->userFSM->getCurrentState()->getName() == Vuba\AuthN\User\UserFSM::USER_STATE_INIT);

        // State wait for confirmation
        $this->userFSM->apply('register');
        $this->assertFalse($this->userFSM->can('login'));

        $this->assertFalse($this->userFSM->can('register'));
        $this->assertFalse($this->userFSM->can('resetpw'));
        $this->assertFalse($this->userFSM->can('login'));

    }
}