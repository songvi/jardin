<?php

namespace Vuba\AuthN\User;

use Finite\StatefulInterface;

class UserObjectState extends  UserObject implements  StatefulInterface
{
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
}
