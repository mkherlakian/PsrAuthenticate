<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\AuthStore;

use Psr\Container\ContainerInterface;
use Assert\Assertion;

class DoctrineFactory
{
    public function __invoke(ContainerInterface $container)
    {
        $doctrineConnection  = $container->get('authentication.authstore.doctrine');
        $jwtParams = $container->get('config')['jwt_params'];

        Assertion::keyExists($jwtParams, 'refresh_expiration');

        $doctrineAuthStore = new Doctrine($doctrineConnection, $jwtParams['refresh_expiration']);

        return $doctrineAuthStore;
    }
}
