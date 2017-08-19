<?php

namespace Vuba\AuthN\UserStorage;

use PHPUnit\Framework\Exception;
use Vuba\AuthN\User\UserObject;
use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;



class UserStorageSql implements IUserStorage
{
    protected $em;

    public function __construct($confService){
        $isDevMode = true;
        $userStorage = $confService->getUserStorage();
        $config = Setup::createYAMLMetadataConfiguration(array($userStorage['mappingpath'], $isDevMode));
        $this->em = EntityManager::create($userStorage['sqlconnection'], $config);
    }

    /**
     *
     */
    public function loadUser($uuid)
    {
        $this->em->clear();
        $userRepo = $this->em->getRepository('Vuba\AuthN\User\UserObject');
        $user = $userRepo->findBy(array('uuid' => $uuid));
        if(count($user) > 0) return $user[0];
        return null;
    }

    /**
     * @param UserObject $userObject
     * @return mixed
     */
    public function save(UserObject $userObject)
    {
        try {
            $result = $this->em->find('Vuba\AuthN\User\UserObject', $userObject->getUuid());
            if ($result) {
                $this->em->merge($userObject);
            } else {
                $this->em->persist($userObject);
            }
            $this->em->flush();
        }catch(Exception $e){
            return false;
        }
        return true;
    }

    /**
     * @param array $criterias
     * @return mixed
     */
    public function search($criterias = array())
    {
        $userRepo = $this->em->getRepository('Vuba\AuthN\User\UserObject');
        $user = $userRepo->findOneBy($criterias);
        return $user;
    }

    /**
     * @return mixed
     */
    public function listUser($page = 0, $offset = 0, $limit = 50)
    {
    
    }

    public function deleteUser($userObject){
        $this->em->remove($userObject);
        $this->em->flush();
    }
    
    /**
     * @param $uid
     * @return bool
     */
    public function isExist($uid)
    {
        $userRepo = $this->em->getRepository('Vuba\AuthN\User\UserObject');
        $user = $userRepo->findBy(array('extuid' => $uid));
        if(!isset($user[0])) return null;
    }    
}
