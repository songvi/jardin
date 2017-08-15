<?php
namespace Vuba\AuthN\Confirmation;

interface IConfirmation {
    public function setDest($destinationAddress);
    public function getDest($destinationAddress);

}
