<?php

namespace Vuba\AuthN\Service;

use Symfony\Component\Yaml\Yaml;

class ConfServiceYaml implements IConfService{

    protected $config;

    public function __construct($yamlFilePath){
        if(!is_file($yamlFilePath)) return null;

        try {
            $this->config = Yaml::parse(file_get_contents($yamlFilePath));
        } catch (ParseException $e) {
            printf("Unable to parse the YAML string from file: %s", $yamlFilePath);
        }
    }
    public function getSqlConnection()
    {
        if(isset($this->config['authentication'])){
            if(isset($this->config['authentication']['sqlconnection'])){
                return $this->config['authentication']['sqlconnection'];
            }
        }
    }

    public function getLdapConnection()
    {
        if(isset($this->config['authentication'])){
            if(isset($this->config['authentication']['ldapconnection'])){
                return $this->config['authentication']['ldapconnection'];
            }
        }
    }

    public function getUserStorageType()
    {
        if(isset($this->config['authentication'])){
            if(isset($this->config['authentication']['userstorage']['type'])){
                return $this->config['authentication']['userstorage']['type'];
            }
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

    public function getAuthType()
    {
        if(isset($this->config['authentication'])){
            if(isset($this->config['authentication']['auth']['type'])){
                return $this->config['authentication']['auth']['type'];
            }
        }
    }

    /**
     * mysql | ldap
     * @return mixed
     */
    public function getAuthStorage()
    {
        if(isset($this->config['authentication'])){
            if(isset($this->config['authentication']['auth'])){
                return $this->config['authentication']['auth'];
            }
        }
    }
}
