<?php

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require __DIR__.'/../vendor/autoload.php';
require __DIR__.'/../config/bootstrap.php';

class UserRepositoryTest extends \PHPUnit\Framework\TestCase
{
    public $userObject;
    public $userFSM;
    public $em;

    public function setup(){

        $config = Setup::createYAMLMetadataConfiguration(array(__DIR__."/../config/yaml"), true);

// database configuration parameters
        $conn = array(
            'driver' => 'mysqli',
            "host" => "127.0.0.1",
            "port" => "3306",
            "user" => "test",
            "password" => "test",
            "dbname" => "authn",
            "charset" => 'utf8'
        );

// obtaining the entity manager
        $this->em = EntityManager::create($conn, $config);
    }

    public function testDatabase(){
        $this->setup();

        $userRepo = $this->em->getRepository('Vuba\AuthN\User\UserObject');

        $user2 = new \Vuba\AuthN\User\UserObject();
        $user2->setState(\Vuba\AuthN\User\UserFSM::USER_STATE_INIT);

        $user2->setExtuid('user2');
        $user2->setAddress('avennue du monde');
        $user2->setBirthdate('1975-01-01 00:00:01');
        $user2->setEmail('email@google.com');
        $user2->setEmailVerified('email@gmail.com');
        $user2->setGender(1);
        $user2->setAuthSourceName('mysql');
        $user2->setUuid(Vuba\AuthN\User\UserObject::calculeUuid($user2->getExtuid(), $user2->getAuthSourceName()));
        $user2->setSub('user2');
        $user2->setName('User 2');
        $user2->setUpdatedAt(time());
        $user2->setLastlogon(time());

        //var_dump($user2);

        $this->em->persist($user2);
        $this->em->flush();
        $user2 = null;

        $user22 = $userRepo->findBy(array('extuid' => 'user2'));

        var_dump($user2);

        $this->assertEquals('user2', $user22->getExtuid());

        if($this->em instanceof EntityManager){
            $this->em->remove($user22);
            $this->em->flush();
        }

    }
}
