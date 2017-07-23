<?php

namespace Vuba\AuthN\UserStorage;

use Symfony\Component\Validator\Tests\Fixtures\Entity;
use Vuba\AuthN\Exception\UserNotFountException;
use Vuba\AuthN\Service\ConfigService;
use Vuba\AuthN\Service\IConfService;
use Vuba\AuthN\User\UserObject;
use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;



class UserStorageSql implements IUserStorage
{

    protected $em;

    public function __construct(IConfService $confService){
        $isDevMode = true;
        $config = Setup::createYAMLMetadataConfiguration(array($confService->getUserStorage()['mappingpath']), $isDevMode);
        $this->em = EntityManager::create($confService->getSqlConnection(), $config);
    }

    /**
     * @param $uid
     * @return mixed
     * @throws \Exception
     *
     */
    public function loadUser($uid)
    {
        $userRepo = $this->em->getRepository('Vuba\AuthN\User\UserObject');
        $user = $userRepo->findBy(array('extuid' => $uid));
        if(!isset($user[0])) return null;

        return $user[0];
    }

    /**
     * @param UserObject $userObject
     * @return mixed
     */
    public function save(UserObject $userObject)
    {
        $result = $this->em->find('Vuba\AuthN\User\UserObject', $userObject->getUuid());
        if($result) {
            $this->em->merge($userObject);
        }
        else {
            $this->em->persist($userObject);
        }
        $this->em->flush();
    }

    /**
     * @param array $criterias
     * @return mixed
     */
    public function search($criterias = array())
    {
        // TODO: Implement search() method.
    }

    /**
     * @return mixed
     */
    public function listUser($page = 0, $offset = 0, $limit = 50)
    {
        // TODO: Implement listUser() method.
    }

    public function deleteUser($userObject){
        $this->em->remove($userObject);
        $this->em->flush();
    }
}