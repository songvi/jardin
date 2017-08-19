<?php

require '../vendor/autoload.php';
require '../src/AuthStack/AuthMySQL.php';
require '../src/User/UserFSM.php';

use \Vuba\AuthN\AuthStack\AuthMySQL;
use \Defuse\Crypto\Key;
use PHPUnit\Framework\TestCase;

class AuthMySQLTest extends TestCase
{
    public $authMySQL;

    public function setUp(){
        $config = new \Vuba\AuthN\Service\ConfServiceYaml(__DIR__.'/../config/config.yml');
        $auths = $config->getAuth();
        foreach ($auths as $auth){
            if($auth['type'] == 'sql'){
                $this->authMySQL = new AuthMySQL($auth['config']);
            }
        }
    }

    public function testCreateUser(){
        $this->setup();
        $uid = '35425';
        $pass = 'P@ssw0rdaaa';
        $this->authMySQL->createUser($uid, $pass);
        $this->assertEquals(1, $this->authMySQL->isExist($uid));
        $this->assertTrue($this->authMySQL->checkPassword($uid, $pass));
        $this->authMySQL->delete(35425);
    }

    public function testDeleteUser(){
        $this->setup();
        $uid = '35425';
        $pass = 'P@s"ésdqdl õ é"*$)àçç)sw0rdaa ` \ | assw0rdaaasdl õ é"*$)àçç)sw0rdaa ` \ | assw0rdaaasdl õ é"*$)àçç)sw0rdaa ` \ | assw0rdaaasdl õ é"*$)àçç)sw0rdaa ` \ | assw0rdaaasdl õ é"*$)àçç)sw0rdaa ` \ | assw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaaP@ssw0rdaaassw0rdaaassw0rdaaassw0rdaaassw0rdaaa';
        $this->authMySQL->createUser($uid, $pass);
        $this->assertTrue($this->authMySQL->isExist(35425));
        $this->assertTrue($this->authMySQL->checkPassword($uid, $pass));
        $this->authMySQL->delete(35425);
        $this->assertFalse($this->authMySQL->isExist(35425));
    }

    public function testChangeState(){
        $this->setup();
        $uid = '35425';
        $pass = 'P@s"ésdqdl õ é"*$)àçç)s';
        $this->authMySQL->delete(35425);
        $this->authMySQL->createUser($uid, $pass);
        $this->assertTrue($this->authMySQL->isExist($uid));
        $this->authMySQL->delete(35425);
    }

    public function tearDown(){

    }
}

