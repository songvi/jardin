<?php

namespace Vuba\AuthN\UserStorage;

use Vuba\AuthN\User\UserObject;

interface IUserStorage
{
    /**
     * @param $uid
     * @return mixed
     */
    public function loadUser($uuid);

    /**
     * @param UserObject $userObject
     * @return mixed
     */
    public function save(UserObject $userObject);

    /**
     * @param array $criterias
     * @return mixed
     */
    public function search($criterias = array());



    /**
     * @return mixed
     */
    public function listUser($page = 0, $offset = 0, $limit = 50);
}
