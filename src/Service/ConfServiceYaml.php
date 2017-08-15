<?php

namespace Vuba\AuthN\Service;

use Symfony\Component\Yaml\Yaml;

class ConfServiceYaml implements  IConfService{

    protected $config;

    public function __construct($yamlFilePath){
        if(!is_file($yamlFilePath)) return null;

        try {
            $this->config = Yaml::parse(file_get_contents($yamlFilePath));
        } catch (\Exception $e) {
            printf("Unable to parse the YAML string from file: %s", $yamlFilePath);
        }
    }
    public function getUserStorage()
    {
        if(isset($this->config['authentication'])){
            if(isset($this->config['authentication']['userstorage'])){
                return $this->config['authentication']['userstorage'];
            }
        }
    }

    public function getAuth()
    {
        if(isset($this->config['authentication'])){
            if(isset($this->config['authentication']['auth'])){
                return $this->config['authentication']['auth'];
            }
        }
    }

    public function getSqlConnection()
    {

    }

    public function getLdapConnection()
    {

    }

    public function getUserStorageType()
    {

    }

    public function getAuthType()
    {

    }

    /**
     * mysql | ldap
     * @return mixed
     */
    public function getAuthStorage()
    {

    }
}
