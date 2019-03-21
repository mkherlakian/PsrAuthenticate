<?php

namespace Mauricek\PsrAuthentication\Middleware;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Mauricek\PsrAuthentication\AuthProvider\AuthValidationProvider;
use Mauricek\PsrAuthentication\Credentials;

class ChainedAuthValidationMiddleware implements MiddlewareInterface
{
    protected $providers;

    public function __construct(...$providers)
    {
        foreach($providers as $provider) {
            if(!$provider instanceof AuthValidationProvider) {
                throw new \InvalidArgumentException("Providers must be of type ".AuthValidationProvider::class);
            }
            $this->providers[] = $provider;
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $delegate) : ResponseInterface
    {
        $identity = null;

        //Go through each group
        //then through each provider
        foreach($this->providers as $provider) {
            $identity = $provider->validate($request);
            if(!is_null($identity)) {
                break;
            }
        }

        if(is_null($identity)) {
            throw new \RuntimeException('Invalid credentials');
        }

        $request = $request->withAttribute(Credentials::class, $identity);
        return $delegate->handle($request);
    }
}
